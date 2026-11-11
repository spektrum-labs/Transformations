"""Cato confirmedLicensePurchased reads data.licensing.licensingInfo.licenses.

The generic affirmative_signal found no recognised key at that depth, so every licensed Cato
account failed.
"""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("catolic", Path(__file__).with_name("confirmedlicensepurchased.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
KEY = "confirmedLicensePurchased"


def lic(status="ACTIVE", expires="2029-06-30T00:00:00.000Z", sku="CATO_SITE"):
    return {"sku": sku, "plan": "COMMERCIAL", "status": status, "expirationDate": expires,
            "startDate": "2023-07-01T00:00:00.000Z"}


def body(licenses):
    return {"data": {"licensing": {"licensingInfo": {"licenses": licenses}}}}


class CatoLicence(unittest.TestCase):
    def res(self, payload):
        return m.transform(payload)["transformedResponse"][KEY]

    def test_active_licence_passes(self):
        self.assertIs(self.res(body([lic(), lic(sku="CATO_THREAT_PREVENTION")])), True)

    def test_graphql_data_already_unwrapped_passes(self):
        self.assertIs(self.res(body([lic()])["data"]), True)

    def test_validation_envelope_passes(self):
        self.assertIs(self.res({"data": body([lic()])["data"], "validation": {"status": "success"}}), True)

    def test_expired_or_inactive_only_fails(self):
        self.assertIs(self.res(body([lic(expires="2020-01-01T00:00:00.000Z"), lic(status="EXPIRED")])), False)

    def test_one_active_among_expired_passes(self):
        self.assertIs(self.res(body([lic(status="EXPIRED"), lic()])), True)

    def test_empty_none_and_errors_fail(self):
        self.assertIs(self.res(body([])), False)
        self.assertIs(self.res({}), False)
        self.assertIs(self.res({"errors": [{"message": "permission denied"}], "data": None}), False)
        self.assertIs(self.res(None), False)


if __name__ == "__main__":
    unittest.main()
