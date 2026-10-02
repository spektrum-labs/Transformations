"""Tests for areadminaccountsseparate.py (Microsoft 365 / Entra ID areAdminAccountsSeparate).

Fixtures follow the Microsoft Graph v1.0 response shapes for
GET /roleManagement/directory/roleAssignments?$expand=principal($select=id) and
GET /users?$select=id,userPrincipalName,mail,accountEnabled,assignedLicenses, merged under
the workflow output keys roleAssignments and users, plus the engine wrappers
(apiResponse / rawResponse / Output) the Integration-Service puts around them.
"""

import importlib.util
import json
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("areadminaccountsseparate.py")
KEY = "areAdminAccountsSeparate"

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de"
DIRECTORY_READERS = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"  # not privileged
SPE_E3 = "05e9a617-0261-4cee-bb44-138d3ef5d965"
ENTRA_P2 = "84a661c4-e949-4bd2-a560-ed7766fcaf2b"  # AAD_PREMIUM_P2: not a productivity licence


def load_transformation():
    spec = importlib.util.spec_from_file_location("ms365_areadminaccountsseparate", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def graph_list(context, rows, next_link=None):
    body = {"@odata.context": f"https://graph.microsoft.com/v1.0/$metadata#{context}", "value": rows}
    if next_link:
        body["@odata.nextLink"] = next_link
    return body


def assignment(principal_id, role=GLOBAL_ADMIN, kind="user"):
    return {
        "id": f"asg-{principal_id}-{role[:8]}",
        "roleDefinitionId": role,
        "principalId": principal_id,
        "directoryScopeId": "/",
        "principal": {"@odata.type": f"#microsoft.graph.{kind}", "id": principal_id},
    }


def user(uid, upn, mail=None, skus=(), enabled=True, plans=None):
    row = {
        "id": uid,
        "userPrincipalName": upn,
        "mail": mail,
        "accountEnabled": enabled,
        "assignedLicenses": [{"disabledPlans": [], "skuId": s} for s in skus],
    }
    if plans is not None:
        row["assignedPlans"] = plans
    return row


DEDICATED_ADMIN = user("u-admin", "admin@contoso.onmicrosoft.com", skus=[ENTRA_P2])
EVERYDAY_USER = user("u-alice", "alice@contoso.com", mail="alice@contoso.com", skus=[SPE_E3])


def merged(assignments, users, assignments_next=None, users_next=None):
    return {
        "roleAssignments": graph_list("roleManagement/directory/roleAssignments", assignments, assignments_next),
        "users": graph_list("users", users, users_next),
    }


class MS365AdminSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def run_t(self, body):
        out = self.t.transform(body)
        return out, out["transformedResponse"], out["additionalInfo"]

    def assert_unevaluated(self, body):
        out, result, info = self.run_t(body)
        self.assertFalse(result[KEY])
        self.assertEqual(info["dataCollection"]["status"], "error", info)
        self.assertTrue(info["dataCollection"]["errors"])
        return info

    # --- pass ---------------------------------------------------------------
    def test_dedicated_admins_pass(self):
        body = merged([assignment("u-admin")], [DEDICATED_ADMIN, EVERYDAY_USER])
        out, result, info = self.run_t(body)
        self.assertTrue(result[KEY], info)
        self.assertEqual(result["adminCount"], 1)
        self.assertEqual(info["dataCollection"]["status"], "success")

    def test_non_privileged_role_on_everyday_user_is_ignored(self):
        body = merged([assignment("u-admin"), assignment("u-alice", role=DIRECTORY_READERS)],
                      [DEDICATED_ADMIN, EVERYDAY_USER])
        self.assertTrue(self.run_t(body)[1][KEY])

    def test_service_principal_role_holder_is_not_judged(self):
        body = merged([assignment("u-admin"), assignment("sp-automation", kind="servicePrincipal")],
                      [DEDICATED_ADMIN])
        out, result, info = self.run_t(body)
        self.assertTrue(result[KEY], info)
        self.assertTrue(any("service principal" in f for f in info["evaluation"]["additionalFindings"]))

    def test_disabled_role_holder_with_mailbox_is_not_a_violation(self):
        stale = user("u-old", "old@contoso.com", mail="old@contoso.com", skus=[SPE_E3], enabled=False)
        body = merged([assignment("u-admin"), assignment("u-old")], [DEDICATED_ADMIN, stale])
        self.assertTrue(self.run_t(body)[1][KEY])

    def test_engine_wrappers_and_json_string(self):
        body = {"apiResponse": merged([assignment("u-admin")], [DEDICATED_ADMIN])}
        self.assertTrue(self.run_t(json.dumps(body))[1][KEY])
        self.assertTrue(self.run_t({"Output": {"rawResponse": merged([assignment("u-admin")], [DEDICATED_ADMIN])}})[1][KEY])

    def test_directory_roles_with_members_is_accepted(self):
        body = {
            "directoryRoles": graph_list("directoryRoles", [
                {"id": "r1", "displayName": "Global Administrator", "roleTemplateId": GLOBAL_ADMIN,
                 "members": [{"@odata.type": "#microsoft.graph.user", "id": "u-admin"}]},
            ]),
            "users": graph_list("users", [DEDICATED_ADMIN]),
        }
        self.assertTrue(self.run_t(body)[1][KEY])

    # --- measured fail ------------------------------------------------------
    def test_global_admin_with_mailbox_and_e3_fails(self):
        body = merged([assignment("u-admin"), assignment("u-alice")], [DEDICATED_ADMIN, EVERYDAY_USER])
        out, result, info = self.run_t(body)
        self.assertFalse(result[KEY])
        self.assertEqual(result["adminsWithMailboxOrLicence"], 1)
        self.assertEqual(info["dataCollection"]["status"], "success")
        self.assertIn("alice@contoso.com", info["evaluation"]["failReasons"][0])

    def test_productivity_licence_without_mail_fails(self):
        licensed = user("u-bob", "bob-admin@contoso.com", skus=[SPE_E3])
        body = merged([assignment("u-bob", role=EXCHANGE_ADMIN)], [licensed])
        self.assertFalse(self.run_t(body)[1][KEY])

    def test_mail_attribute_backstops_an_unlisted_sku(self):
        mailbox = user("u-carol", "carol@contoso.com", mail="carol@contoso.com", skus=["00000000-0000-0000-0000-000000000001"])
        self.assertFalse(self.run_t(merged([assignment("u-carol")], [mailbox]))[1][KEY])

    def test_enabled_exchange_plan_fails(self):
        plans = [{"service": "exchange", "capabilityStatus": "Enabled", "servicePlanId": "x"}]
        mailbox = user("u-dan", "dan@contoso.com", skus=["00000000-0000-0000-0000-000000000002"], plans=plans)
        self.assertFalse(self.run_t(merged([assignment("u-dan")], [mailbox]))[1][KEY])

    def test_violation_is_measured_even_when_read_is_truncated(self):
        body = merged([assignment("u-alice")], [EVERYDAY_USER], users_next="https://graph.microsoft.com/next")
        out, result, info = self.run_t(body)
        self.assertFalse(result[KEY])
        self.assertEqual(info["dataCollection"]["status"], "success")

    # --- not evaluated (fail closed) ----------------------------------------
    def test_secure_score_body_is_not_evidence(self):
        body = {"value": [{"id": "t_2026-10-01", "currentScore": 50, "controlScores": [
            {"controlName": "mdo_blockmailforward", "scoreInPercentage": 100.0}]}]}
        info = self.assert_unevaluated(body)
        self.assertIn("Secure Score", info["dataCollection"]["errors"][0])

    def test_no_privileged_holders_is_incomplete(self):
        self.assert_unevaluated(merged([], [DEDICATED_ADMIN, EVERYDAY_USER]))

    def test_role_holder_missing_from_user_read_is_unresolved(self):
        info = self.assert_unevaluated(merged([assignment("u-admin"), assignment("u-ghost")], [DEDICATED_ADMIN]))
        self.assertTrue(any("u-ghost" in e for e in info["dataCollection"]["errors"]))

    def test_group_role_holder_is_unresolved(self):
        self.assert_unevaluated(merged([assignment("u-admin"), assignment("g-admins", kind="group")], [DEDICATED_ADMIN]))

    def test_truncated_clean_read_is_incomplete(self):
        self.assert_unevaluated(merged([assignment("u-admin")], [DEDICATED_ADMIN], assignments_next="https://next"))

    def test_user_read_without_licence_field_is_incomplete(self):
        bare = {"id": "u-admin", "userPrincipalName": "admin@contoso.onmicrosoft.com", "mail": None}
        self.assert_unevaluated(merged([assignment("u-admin")], [bare]))

    def test_users_only_is_incomplete(self):
        self.assert_unevaluated({"users": graph_list("users", [DEDICATED_ADMIN])})

    def test_roles_only_is_incomplete(self):
        self.assert_unevaluated({"roleAssignments": graph_list("x", [assignment("u-admin")])})

    def test_error_bodies_are_unevaluated(self):
        for body in [
            {"PSError": "Authorization_RequestDenied: Insufficient privileges"},
            {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
            {"statusCode": 403, "error": "Forbidden"},
            {"roleAssignments": {"error": {"code": "Forbidden", "message": "403"}}, "users": graph_list("users", [DEDICATED_ADMIN])},
        ]:
            self.assert_unevaluated(body)

    def test_no_evidence_bodies_never_pass(self):
        for body in [{}, None, "{}", {"hello": "world"}, {"value": []}, []]:
            out, result, info = self.run_t(body)
            self.assertFalse(result[KEY], body)

    def test_malformed_json_fails(self):
        out, result, info = self.run_t("{not json")
        self.assertFalse(result[KEY])
        self.assertEqual(info["transformation"]["status"], "error")

    def test_tenant_supplied_names_are_bounded(self):
        long_upn = "x" * 500 + "@contoso.com"
        body = merged([assignment("u-long")], [user("u-long", long_upn, mail=long_upn)])
        reason = self.run_t(body)[2]["evaluation"]["failReasons"][0]
        self.assertLess(len(reason), 400)


if __name__ == "__main__":
    unittest.main()
