"""Bitsight confirmedLicensePurchased reads subscription_type and subscription_end_date.

The generic affirmative_signal looked for keys such as licensed or subscribed, which the
company-details body does not have, so every subscribed Bitsight company failed.
"""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("bslic", Path(__file__).with_name("confirmedlicensepurchased.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
KEY = "confirmedLicensePurchased"


def company(subscription_type="continuous_monitoring", end=None):
    return {"guid": "00000000-0000-4000-8000-000000000001", "name": "Example Co", "type": "CURATED",
            "subscription_type": subscription_type, "subscription_end_date": end,
            "ratings": [{"rating_date": "2026-01-01", "rating": 750}]}


class BitsightLicence(unittest.TestCase):
    def res(self, payload):
        return m.transform(payload)["transformedResponse"][KEY]

    def test_open_ended_subscription_passes(self):
        self.assertIs(self.res(company()), True)

    def test_future_end_date_passes(self):
        self.assertIs(self.res(company(end="2099-12-31")), True)

    def test_validation_envelope_passes(self):
        self.assertIs(self.res({"data": company(), "validation": {"status": "success"}}), True)

    def test_lapsed_subscription_fails(self):
        self.assertIs(self.res(company(end="2020-01-01")), False)

    def test_no_subscription_fails(self):
        self.assertIs(self.res(company(subscription_type=None)), False)
        self.assertIs(self.res(company(subscription_type="")), False)

    def test_empty_none_and_errors_fail(self):
        self.assertIs(self.res({}), False)
        self.assertIs(self.res(None), False)
        self.assertIs(self.res({"detail": "You do not have permission to perform this action."}), False)
        self.assertIs(self.res({"errors": ["forbidden"], "subscription_type": "x"}), False)


if __name__ == "__main__":
    unittest.main()
