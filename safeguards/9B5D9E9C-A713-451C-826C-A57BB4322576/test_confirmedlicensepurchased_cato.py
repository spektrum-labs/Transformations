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

    def test_date_only_and_today_expiry_pass(self):
        import datetime as dt
        today = dt.datetime.utcnow().date().isoformat()
        self.assertIs(self.res(body([lic(expires="2029-06-30")])), True)
        self.assertIs(self.res(body([lic(expires=today)])), True)

    def test_missing_expiry_passes(self):
        self.assertIs(self.res(body([lic(expires=None)])), True)
        self.assertIs(self.res(body([lic(expires="")])), True)

    def test_unreadable_expiry_fails_closed(self):
        for expires in ("Jun 30, 2029", "06/30/2029", "2029-6-30", 1893456000000, "not a date"):
            with self.subTest(expires=expires):
                self.assertIs(self.res(body([lic(expires=expires)])), False)

    def test_empty_none_and_errors_fail(self):
        self.assertIs(self.res(body([])), False)
        self.assertIs(self.res({}), False)
        self.assertIs(self.res({"errors": [{"message": "permission denied"}], "data": None}), False)
        self.assertIs(self.res(None), False)

    def test_partial_graphql_errors_judged_on_licences(self):
        # GraphQL can return field errors beside data it did resolve. The licences that came back are
        # real, so they decide; an error with no licence data still fails (test above).
        payload = body([lic()])
        payload["errors"] = [{"message": "field unavailable"}]
        self.assertIs(self.res(payload), True)
        payload = body([lic(status="EXPIRED")])
        payload["errors"] = [{"message": "field unavailable"}]
        self.assertIs(self.res(payload), False)


if __name__ == "__main__":
    unittest.main()
