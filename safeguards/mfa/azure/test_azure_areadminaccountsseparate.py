"""Azure AD areAdminAccountsSeparate (mfa/azure/areadminaccountsseparate.py).

2026-10-03 false-fail check:
  * AA-2: a feed with no role or licence data (the bare GET /v1.0/users that Azure AD sends
    today) reads not evaluated, never FAIL.
  * AA-3 (J.J., 3 Oct 2026): a privileged role holder whose only signal is a non-empty `mail`
    is a finding, not a fail. Fail only on a productivity licence or an enabled Exchange plan.
"""

import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("areadminaccountsseparate.py")
KEY = "areAdminAccountsSeparate"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
SPE_E3 = "05e9a617-0261-4cee-bb44-138d3ef5d965"
EXCHANGE_PLAN_2 = "19ec0d23-8335-4cbd-94ac-6050e30712fa"
ENTRA_P2 = "84a661c4-e949-4bd2-a560-ed7766fcaf2b"


def load():
    spec = importlib.util.spec_from_file_location("azure_areadminaccountsseparate", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def user(uid, upn, mail=None, skus=(), plans=None):
    row = {"id": uid, "userPrincipalName": upn, "mail": mail,
           "assignedLicenses": [{"disabledPlans": [], "skuId": s} for s in skus]}
    if plans is not None:
        row["assignedPlans"] = plans
    return row


def body(users, admin_ids):
    return {
        "roleAssignments": {"value": [{"roleDefinitionId": GLOBAL_ADMIN, "principalId": i} for i in admin_ids]},
        "users": {"value": users},
    }


class AzureAdminSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, data):
        out = self.t.transform(data)
        return out["transformedResponse"], out["additionalInfo"]

    def assert_not_evaluated(self, data):
        result, info = self.run_t(data)
        self.assertFalse(result[KEY])
        self.assertEqual(info["dataCollection"]["status"], "error", info)
        self.assertTrue(info["dataCollection"]["errors"])
        self.assertEqual(info["evaluation"]["failReasons"], [])

    # --- AA-2: no data is not evaluated --------------------------------------
    def test_bare_user_feed_without_role_or_licence_data_is_not_evaluated(self):
        bare = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
                "value": [{"id": "u1", "userPrincipalName": "a@contoso.com", "mail": "a@contoso.com"}]}
        self.assert_not_evaluated(bare)
        self.assert_not_evaluated({"apiResponse": bare})

    def test_role_data_without_licence_field_is_not_evaluated(self):
        no_licences = {"roleAssignments": {"value": [{"roleDefinitionId": GLOBAL_ADMIN, "principalId": "u1"}]},
                       "users": {"value": [{"id": "u1", "userPrincipalName": "a@contoso.com"}]}}
        self.assert_not_evaluated(no_licences)

    def test_licences_without_role_data_is_not_evaluated(self):
        self.assert_not_evaluated({"value": [user("u1", "a@contoso.com", skus=[SPE_E3])]})

    def test_empty_and_error_bodies_are_not_evaluated(self):
        for data in ({}, {"value": []}, [],
                     {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}):
            with self.subTest(data=data):
                self.assert_not_evaluated(data)

    def test_admin_missing_from_user_feed_is_not_evaluated(self):
        self.assert_not_evaluated(body([user("u1", "admin@contoso.onmicrosoft.com", skus=[ENTRA_P2])], ["u1", "u-ghost"]))

    # --- AA-3: mail alone is a finding ---------------------------------------
    def test_mail_attribute_alone_is_a_finding_not_a_fail(self):
        admin = user("u1", "admin@contoso.com", mail="admin@contoso.com", skus=[ENTRA_P2])
        result, info = self.run_t(body([admin], ["u1"]))
        self.assertTrue(result[KEY], info)
        self.assertEqual(info["dataCollection"]["status"], "success")
        self.assertEqual(info["evaluation"]["failReasons"], [])
        self.assertEqual(result["adminsWithMailLicense"], 0)
        self.assertEqual(result["adminsWithMailAttributeOnly"], 1)
        self.assertIn("not a fail", " ".join(info["evaluation"]["additionalFindings"]))

    def test_productivity_sku_fails(self):
        for sku in (SPE_E3, EXCHANGE_PLAN_2):
            with self.subTest(sku=sku):
                for mail in (None, "admin@contoso.com"):
                    result, info = self.run_t(body([user("u1", "admin@contoso.com", mail=mail, skus=[sku])], ["u1"]))
                    self.assertFalse(result[KEY])
                    self.assertEqual(info["dataCollection"]["status"], "success")
                    self.assertTrue(info["evaluation"]["failReasons"])

    def test_enabled_exchange_plan_fails(self):
        plans = [{"service": "exchange", "capabilityStatus": "Enabled", "servicePlanId": "x"}]
        result, info = self.run_t(body([user("u1", "admin@contoso.com", mail="admin@contoso.com", plans=plans)], ["u1"]))
        self.assertFalse(result[KEY])
        self.assertEqual(info["dataCollection"]["status"], "success")

    def test_dedicated_admin_passes(self):
        result, info = self.run_t(body([user("u1", "admin@contoso.onmicrosoft.com", skus=[ENTRA_P2])], ["u1"]))
        self.assertTrue(result[KEY], info)
        self.assertEqual(info["evaluation"]["additionalFindings"], [])


if __name__ == "__main__":
    unittest.main()
