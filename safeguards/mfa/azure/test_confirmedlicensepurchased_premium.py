"""Azure AD confirmedLicensePurchased requires an enabled Entra ID P1/P2 plan on /organization.

Every tenant has an organization record (and Entra ID Free), which the old affirmative_signal rule
counted as a licence.
"""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("azlic", Path(__file__).with_name("confirmedlicensepurchased.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
KEY = "confirmedLicensePurchased"


def org(*plans):
    return {"value": [{"id": "t1", "displayName": "Contoso", "assignedPlans": list(plans)}]}


def plan(service, status="Enabled", plan_id="00000000-0000-0000-0000-000000000000"):
    return {"assignedDateTime": "2026-01-01T00:00:00Z", "capabilityStatus": status, "service": service, "servicePlanId": plan_id}


class AzureLicence(unittest.TestCase):
    def res(self, payload):
        return m.transform(payload)["transformedResponse"][KEY]

    def test_enabled_premium_passes(self):
        self.assertIs(self.res(org(plan("exchange"), plan("AADPremiumService", plan_id="41781fb2-bc02-4b7c-bd55-b576c07bb09d"))), True)

    def test_free_tenant_fails(self):
        self.assertIs(self.res(org(plan("exchange"), plan("SharePoint"))), False)

    def test_suspended_premium_fails(self):
        self.assertIs(self.res(org(plan("AADPremiumService", "Suspended"))), False)

    def test_record_without_plans_and_errors_fail(self):
        self.assertIs(self.res({"value": [{"id": "t1"}]}), False)
        self.assertIs(self.res({"error": {"code": "Authorization_RequestDenied"}}), False)
        self.assertIs(self.res({}), False)


if __name__ == "__main__":
    unittest.main()
