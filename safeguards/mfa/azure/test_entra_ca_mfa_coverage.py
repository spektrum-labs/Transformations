"""Azure AD One-Click isRDPProtected / isMFARequiredForRemoteAccess: Conditional Access coverage.

Fixtures follow GET /v1.0/identity/conditionalAccess/policies (conditionalAccessPolicy) and
GET /v1.0/groups (group: groupTypes, membershipRule, membershipRuleProcessingState). Policy shapes mirror the
ten tenants that read "not evaluated" on 2 Oct 2026 (names anonymised): an MFA policy on a dynamic all-staff
group, a browser plus desktop-clients pair, an assigned group, a location-scoped pair and a group missing from
the group list.
"""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("cacoverage", Path(__file__).with_name("entra_ca_mfa_coverage.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

CTX = "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies"
G_DYN = "11111111-1111-1111-1111-111111111111"
G_ASSIGNED = "22222222-2222-2222-2222-222222222222"
G_DYN_DEPT = "33333333-3333-3333-3333-333333333333"


def policy(name, groups=None, users=None, clients=None, locations=None, state="enabled", controls=("mfa",)):
    conditions = {
        "applications": {"includeApplications": ["All"]},
        "users": {"includeUsers": users or [], "includeGroups": groups or [], "includeRoles": [],
                  "excludeUsers": ["breakglass-1"], "excludeGroups": []},
        "clientAppTypes": clients or ["all"],
    }
    if locations is not None:
        conditions["locations"] = locations
    return {"id": name, "displayName": name, "state": state, "conditions": conditions,
            "grantControls": {"operator": "OR", "builtInControls": list(controls)}}


def ca(*policies):
    return {"@odata.context": CTX, "value": list(policies)}


def groups(*items):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups", "value": list(items)}


def group(gid, rule=None, dynamic=True, state="On"):
    return {"id": gid, "displayName": gid[:4], "groupTypes": ["DynamicMembership"] if dynamic else [],
            "membershipRule": rule, "membershipRuleProcessingState": state if dynamic else None}


ALL_GROUPS = groups(
    group(G_DYN, '(user.accountEnabled -eq true) -and (user.userType -eq "Member")'),
    group(G_ASSIGNED, dynamic=False),
    group(G_DYN_DEPT, '(user.department -eq "Finance")'),
)


def run(policies, grp=ALL_GROUPS):
    out = m.transform({"conditionalAccessPolicies": policies, "groups": grp})
    return out["transformedResponse"], out["additionalInfo"]


class Coverage(unittest.TestCase):
    def test_dynamic_all_users_group_counts_as_all_users(self):
        res, info = run(ca(policy("MFA - All staff (dynamic)", groups=[G_DYN])))
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertIs(res["isRDPProtected"], True)
        self.assertEqual(info["dataCollection"]["status"], "success")

    def test_assigned_group_stays_not_evaluated(self):
        res, info = run(ca(policy("MFA Standard users", groups=[G_ASSIGNED])))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertEqual(info["dataCollection"]["status"], "error")

    def test_department_dynamic_group_is_not_all_users(self):
        res, _ = run(ca(policy("MFA Finance", groups=[G_DYN_DEPT])))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_group_missing_from_list_stays_not_evaluated(self):
        res, _ = run(ca(policy("MFA unknown group", groups=["44444444-4444-4444-4444-444444444444"])))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_rule_processing_paused_is_not_all_users(self):
        grp = groups(group(G_DYN, "(user.accountEnabled -eq true)", state="Paused"))
        res, _ = run(ca(policy("MFA all", groups=[G_DYN])), grp)
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_or_rule_is_not_all_users(self):
        grp = groups(group(G_DYN, '(user.accountEnabled -eq true) -or (user.department -eq "x")'))
        res, _ = run(ca(policy("MFA all", groups=[G_DYN])), grp)
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_browser_plus_desktop_pair_covers_all_clients(self):
        res, _ = run(ca(
            policy("Baseline MFA Browser", users=["All"], clients=["browser"]),
            policy("Baseline MFA Desktop clients", users=["All"], clients=["mobileAppsAndDesktopClients"]),
        ))
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertEqual(sorted(res["remoteAccessPolicies"]), ["Baseline MFA Browser", "Baseline MFA Desktop clients"])

    def test_browser_only_stays_not_evaluated(self):
        res, _ = run(ca(policy("MFA Browser only", users=["All"], clients=["browser"])))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_pair_on_assigned_group_stays_not_evaluated(self):
        res, _ = run(ca(
            policy("MFA Browser", groups=[G_ASSIGNED], clients=["browser"]),
            policy("MFA Desktop", groups=[G_ASSIGNED], clients=["mobileAppsAndDesktopClients"]),
        ))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_location_scoped_pair_stays_not_evaluated(self):
        loc = {"includeLocations": ["named-external"], "excludeLocations": []}
        res, _ = run(ca(
            policy("MFA External browser", users=["All"], clients=["browser"], locations=loc),
            policy("MFA External desktop", users=["All"], clients=["mobileAppsAndDesktopClients"], locations=loc),
        ))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_report_only_policy_does_not_count(self):
        res, _ = run(ca(policy("MFA all (report only)", groups=[G_DYN], state="enabledForReportingButNotEnforced"),
                        policy("Block legacy auth", users=["All"], controls=("block",))))
        self.assertIs(res["isMFARequiredForRemoteAccess"], False)

    def test_paged_group_list_resolves_nothing(self):
        grp = dict(ALL_GROUPS)
        grp["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/groups?$skiptoken=x"
        res, _ = run(ca(policy("MFA - All staff (dynamic)", groups=[G_DYN])), grp)
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_legacy_bare_policy_list_still_works(self):
        out = m.transform(ca(policy("MFA everyone", users=["All"])))
        self.assertIs(out["transformedResponse"]["isMFARequiredForRemoteAccess"], True)

    def test_no_enabled_policy_is_not_evaluated(self):
        res, info = run(ca())
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertEqual(info["dataCollection"]["status"], "error")

    def test_error_body_fails_closed(self):
        out = m.transform({"conditionalAccessPolicies": {"error": {"code": "Forbidden"}}, "groups": ALL_GROUPS})
        self.assertIsNone(out["transformedResponse"]["isMFARequiredForRemoteAccess"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")



# GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy, the documented response shape.
SD_CTX = "https://graph.microsoft.com/v1.0/$metadata#policies/identitySecurityDefaultsEnforcementPolicy/$entity"


def security_defaults(enabled):
    return {"@odata.context": SD_CTX, "id": "00000000-0000-0000-0000-000000000005",
            "displayName": "Security Defaults",
            "description": "Security defaults is a set of basic identity security mechanisms recommended by Microsoft.",
            "isEnabled": enabled}


def run_sd(policies, sd):
    out = m.transform({"conditionalAccessPolicies": policies, "groups": ALL_GROUPS, "securityDefaults": sd})
    return out["transformedResponse"], out["additionalInfo"]


class SecurityDefaults(unittest.TestCase):
    """No Conditional Access policy enabled (an estate with no enabled policy): read security defaults."""

    def test_real_shape_security_defaults_on_passes_both_keys(self):
        res, info = run_sd(ca(), security_defaults(True))
        self.assertIs(res["isRDPProtected"], True)
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertIs(res["securityDefaultsEnabled"], True)
        self.assertEqual(res["rdpPolicies"], ["Security defaults"])
        self.assertEqual(info["dataCollection"]["status"], "success")
        self.assertTrue(all("security defaults are on" in r for r in info["evaluation"]["passReasons"]))
        self.assertEqual(len(info["evaluation"]["passReasons"]), 2)

    def test_flipped_security_defaults_off_stays_not_evaluated(self):
        res, info = run_sd(ca(), security_defaults(False))
        self.assertIsNone(res["isRDPProtected"])
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertIs(res["securityDefaultsEnabled"], False)
        self.assertEqual(info["dataCollection"]["status"], "error")
        self.assertTrue(all("security defaults are off" in e for e in info["dataCollection"]["errors"]))

    def test_report_only_policies_with_security_defaults_on_pass(self):
        res, _ = run_sd(ca(policy("MFA all (report only)", users=["All"], state="enabledForReportingButNotEnforced")),
                        security_defaults(True))
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)

    def test_string_booleans_are_read(self):
        res, _ = run_sd(ca(), security_defaults("True"))
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        res, _ = run_sd(ca(), security_defaults("false"))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertIs(res["securityDefaultsEnabled"], False)

    def test_list_wrapped_body_is_read(self):
        res, _ = run_sd(ca(), [security_defaults(True)])
        self.assertIs(res["isRDPProtected"], True)

    def test_empty_security_defaults_body_changes_nothing(self):
        for body in ({}, [], ""):
            res, info = run_sd(ca(), body)
            self.assertIsNone(res["isMFARequiredForRemoteAccess"], body)
            self.assertIsNone(res["securityDefaultsEnabled"], body)
            self.assertIn("security defaults or per-user MFA may apply", info["dataCollection"]["errors"][0])

    def test_none_security_defaults_changes_nothing(self):
        res, info = run_sd(ca(), None)
        self.assertIsNone(res["isRDPProtected"])
        self.assertIn("security defaults or per-user MFA may apply", info["dataCollection"]["errors"][0])

    def test_error_security_defaults_body_changes_nothing(self):
        res, info = run_sd(ca(), {"error": {"code": "Authorization_RequestDenied",
                                            "message": "Insufficient privileges to complete the operation."}})
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertEqual(info["dataCollection"]["status"], "error")

    def test_missing_is_enabled_changes_nothing(self):
        body = security_defaults(True)
        del body["isEnabled"]
        res, _ = run_sd(ca(), body)
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        res, _ = run_sd(ca(), security_defaults(None))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_unrelated_body_with_is_enabled_is_not_trusted(self):
        res, _ = run_sd(ca(), {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/"
                                                 "authenticationMethodsPolicy/$entity", "isEnabled": True})
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_not_consulted_when_a_policy_is_enabled(self):
        # Group-scoped policy enabled: the answer stays the group-scope one even if a body claims defaults are on.
        res, info = run_sd(ca(policy("MFA Standard users", groups=[G_ASSIGNED])), security_defaults(True))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertIn("scoped to user groups", info["dataCollection"]["errors"][0])
        # Enabled policies that require no workforce MFA still fail.
        res, _ = run_sd(ca(policy("Block legacy auth", users=["All"], controls=("block",))), security_defaults(True))
        self.assertIs(res["isMFARequiredForRemoteAccess"], False)

    def test_error_ca_body_with_security_defaults_on_fails_closed(self):
        out = m.transform({"conditionalAccessPolicies": {"error": {"code": "Forbidden"}}, "groups": ALL_GROUPS,
                           "securityDefaults": security_defaults(True)})
        self.assertIsNone(out["transformedResponse"]["isRDPProtected"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_paged_ca_list_with_security_defaults_on_fails_closed(self):
        body = ca()
        body["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=x"
        res, _ = run_sd(body, security_defaults(True))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_none_input_fails_closed(self):
        out = m.transform(None)
        self.assertIsNone(out["transformedResponse"]["isRDPProtected"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
