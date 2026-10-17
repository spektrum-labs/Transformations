"""Cato confirmedLicensePurchased reads the licensing body the vendor actually returns.

The licence call answers {"licensing": {"licensingInfo": {"licenses": [...]}}}. The transform
fell back to a generic signal that knows none of those keys, so a tenant with every licence
ACTIVE read False. All fixtures are synthetic.
"""
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("cato_licence", HERE / "confirmedlicensepurchased.py")
lic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lic)
KEY = "confirmedLicensePurchased"


def body(*licenses, wrapped=False):
    out = {"licensing": {"licensingInfo": {"licenses": list(licenses)}}}
    return {"data": out} if wrapped else out


def entry(status="ACTIVE", expires="2999-01-01T00:00:00.000Z"):
    item = {"sku": "SYNTHETIC_SKU", "plan": "COMMERCIAL", "status": status}
    if expires is not None:
        item["expirationDate"] = expires
    return item


class CatoLicence(unittest.TestCase):
    def res(self, payload):
        return lic.transform(payload)["transformedResponse"][KEY]

    def test_active_licence_passes(self):
        self.assertIs(self.res(body(entry())), True)

    def test_wrapped_in_data_passes(self):
        self.assertIs(self.res(body(entry(), wrapped=True)), True)

    def test_no_expiry_passes(self):
        self.assertIs(self.res(body(entry(expires=None))), True)

    def test_one_active_among_lapsed_passes(self):
        self.assertIs(self.res(body(entry("EXPIRED"), entry())), True)

    def test_only_expired_status_fails(self):
        self.assertIs(self.res(body(entry("EXPIRED"))), False)

    def test_active_but_past_expiry_fails(self):
        self.assertIs(self.res(body(entry(expires="2001-01-01T00:00:00.000Z"))), False)

    def test_unreadable_expiry_is_not_evidence(self):
        self.assertIs(self.res(body(entry(expires="soon"))), False)

    def test_empty_list_fails(self):
        self.assertIs(self.res(body()), False)

    def test_error_body_fails(self):
        self.assertIs(self.res({"errors": [{"message": "denied"}]}), False)

    def test_unrecognised_body_fails(self):
        self.assertIs(self.res({"unrelated": 1}), False)


if __name__ == "__main__":
    unittest.main()
