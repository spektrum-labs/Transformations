"""Bitsight confirmedLicensePurchased reads the subscription fields of the company profile.

Bitsight has no licence endpoint; the company profile carries subscription_type_key and
subscription_end_date. The transform fell back to a generic signal that knows neither, so a
subscribed tenant read False. All fixtures are synthetic.
"""
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("bitsight_licence", HERE / "confirmedlicensepurchased.py")
lic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lic)
KEY = "confirmedLicensePurchased"


def profile(**fields):
    base = {"guid": "00000000-0000-0000-0000-000000000000", "name": "Synthetic Co",
            "subscription_type": "MySubsidiary", "subscription_type_key": "my_subsidiary",
            "subscription_end_date": None, "current_rating": 700}
    base.update(fields)
    return base


class BitsightLicence(unittest.TestCase):
    def res(self, payload):
        return lic.transform(payload)["transformedResponse"][KEY]

    def test_open_ended_subscription_passes(self):
        self.assertIs(self.res(profile()), True)

    def test_future_end_date_passes(self):
        self.assertIs(self.res(profile(subscription_end_date="2999-01-01")), True)

    def test_past_end_date_fails(self):
        self.assertIs(self.res(profile(subscription_end_date="2001-01-01")), False)

    def test_unreadable_end_date_is_not_evidence(self):
        self.assertIs(self.res(profile(subscription_end_date="soon")), False)

    def test_empty_subscription_type_fails(self):
        self.assertIs(self.res(profile(subscription_type_key="")), False)

    def test_error_body_fails(self):
        self.assertIs(self.res({"errors": [{"message": "denied"}]}), False)

    def test_unrecognised_body_fails(self):
        self.assertIs(self.res({"unrelated": 1}), False)


if __name__ == "__main__":
    unittest.main()
