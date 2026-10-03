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

    def test_real_shape_security_defaults_on_never_passes_and_names_the_next_step(self):
        res, info = run_sd(ca(), security_defaults(True))
        self.assertIsNone(res["isRDPProtected"])
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertIs(res["securityDefaultsEnabled"], True)
        self.assertEqual(res["rdpPolicies"], [])
        self.assertEqual(info["dataCollection"]["status"], "error")
        errors = info["dataCollection"]["errors"]
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("Security defaults are on" in e and "Conditional Access policy requiring MFA" in e
                            and "attest" in e for e in errors))
        self.assertTrue(any("Remote Desktop" in e for e in errors if e.startswith("isRDPProtected")))
        self.assertFalse(info["evaluation"]["passReasons"])

    def test_flipped_security_defaults_off_stays_not_evaluated(self):
        res, info = run_sd(ca(), security_defaults(False))
        self.assertIsNone(res["isRDPProtected"])
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertIs(res["securityDefaultsEnabled"], False)
        self.assertEqual(info["dataCollection"]["status"], "error")
        self.assertTrue(all("security defaults are off" in e for e in info["dataCollection"]["errors"]))

    def test_report_only_policies_with_security_defaults_on_do_not_pass(self):
        res, _ = run_sd(ca(policy("MFA all (report only)", users=["All"], state="enabledForReportingButNotEnforced")),
                        security_defaults(True))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])

    def test_string_booleans_are_read(self):
        res, _ = run_sd(ca(), security_defaults("True"))
        self.assertIs(res["securityDefaultsEnabled"], True)
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        res, _ = run_sd(ca(), security_defaults("false"))
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertIs(res["securityDefaultsEnabled"], False)

    def test_list_wrapped_body_is_read(self):
        res, _ = run_sd(ca(), [security_defaults(True)])
        self.assertIs(res["securityDefaultsEnabled"], True)
        self.assertIsNone(res["isRDPProtected"])

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


# Group membership read (3 Oct 2026). Shapes follow GET /v1.0/users?$select=id,accountEnabled,userType&$filter=
# accountEnabled eq true and userType eq 'Member'&$count=true (ConsistencyLevel: eventual) and GET /v1.0/groups/{id}/
# transitiveMembers/microsoft.graph.user?$select=id&$count=true, as the Integration-Service workflow merges them.
# Estate A is synthetic: four enabled member accounts, a guest and a disabled account.
U1 = "a0000000-0000-0000-0000-000000000001"
U2 = "a0000000-0000-0000-0000-000000000002"
U3 = "a0000000-0000-0000-0000-000000000003"
U4 = "a0000000-0000-0000-0000-000000000004"
GUEST = "a0000000-0000-0000-0000-0000000000f1"
DISABLED = "a0000000-0000-0000-0000-0000000000d1"
G_STAFF = "55555555-5555-5555-5555-555555555555"
G_SALES = "66666666-6666-6666-6666-666666666666"
G_OPS = "77777777-7777-7777-7777-777777777777"
G_BREAKGLASS = "88888888-8888-8888-8888-888888888888"
NAMED = groups(group(G_ASSIGNED, dynamic=False), group(G_STAFF, dynamic=False), group(G_SALES, dynamic=False),
               group(G_OPS, dynamic=False), group(G_BREAKGLASS, dynamic=False))
USERS_CTX = "https://graph.microsoft.com/v1.0/$metadata#users(id,accountEnabled,userType)"
MEMBERS_CTX = "https://graph.microsoft.com/v1.0/$metadata#users(id)"


def workforce(*ids, count=True, extra=()):
    value = [{"id": uid, "accountEnabled": True, "userType": "Member"} for uid in ids] + list(extra)
    body = {"@odata.context": USERS_CTX, "value": value}
    if count:
        body["@odata.count"] = len(value)
    return body


def members(*ids, count=True):
    body = {"@odata.context": MEMBERS_CTX,
            "value": [{"@odata.type": "#microsoft.graph.user", "id": uid} for uid in ids]}
    if count:
        body["@odata.count"] = len(ids)
    return body


NOT_FOUND = {"vendorErrorAsResponse": {"status": 404, "bodyContains": "Request_ResourceNotFound", "body": {
    "error": {"code": "Request_ResourceNotFound", "message": "Resource does not exist or one of its queried "
                                                             "reference-property objects are not present."}}}}


def gpolicy(name, include, exclude=(), exclude_users=(), include_users=(), **kw):
    p = policy(name, groups=list(include), users=list(include_users), **kw)
    p["conditions"]["users"]["excludeGroups"] = list(exclude)
    p["conditions"]["users"]["excludeUsers"] = list(exclude_users)
    return p


def run_members(policies, users, group_bodies, grp=NAMED):
    """group_bodies: [(group id, member body), ...] in the order the workflow read them."""
    out = m.transform({"conditionalAccessPolicies": policies, "groups": grp, "workforceUsers": users,
                       "caPolicyGroups": {"groupIds": [{"id": gid} for gid, _ in group_bodies]},
                       "groupMembers": [body for _, body in group_bodies]})
    return out["transformedResponse"], out["additionalInfo"]


class GroupMembership(unittest.TestCase):
    def assert_unevaluated(self, res, info):
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertIsNone(res["isRDPProtected"])
        self.assertEqual(info["dataCollection"]["status"], "error")
        self.assertFalse(info["evaluation"]["passReasons"])

    def test_one_group_holding_every_enabled_member_covers_the_workforce(self):
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), workforce(U1, U2, U3, U4),
                                [(G_STAFF, members(U1, U2, U3, U4))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertIs(res["isRDPProtected"], True)
        self.assertEqual(info["dataCollection"]["status"], "success")
        cov = res["remoteAccessPoliciesGroupCoverage"]
        self.assertEqual((cov["membersTotal"], cov["membersCovered"], cov["excludedCount"], cov["uncoveredCount"]),
                         (4, 4, 0, 0))
        self.assertEqual(cov["groupsUsed"], [G_STAFF[:4]])
        self.assertEqual(res["remoteAccessPolicies"], ["MFA Standard users"])
        self.assertIn("all 4 enabled member accounts are in the included groups", info["evaluation"]["passReasons"][1])

    def test_output_carries_counts_and_group_names_never_user_ids(self):
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), workforce(U1, U2, U3, U4),
                                [(G_STAFF, members(U1, U2, U3))])
        text = str(res) + str(info)
        for uid in (U1, U2, U3, U4):
            self.assertNotIn(uid, text)

    def test_union_of_two_policies_on_two_groups(self):
        res, _ = run_members(ca(gpolicy("MFA Sales", [G_SALES]), gpolicy("MFA Ops", [G_OPS])),
                             workforce(U1, U2, U3, U4),
                             [(G_SALES, members(U1, U2)), (G_OPS, members(U3, U4))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertEqual(sorted(res["remoteAccessPolicies"]), ["MFA Ops", "MFA Sales"])
        self.assertEqual(res["remoteAccessPoliciesGroupCoverage"]["membersCovered"], 4)

    def test_union_of_two_groups_in_one_policy(self):
        res, _ = run_members(ca(gpolicy("MFA Sales and Ops", [G_SALES, G_OPS])), workforce(U1, U2, U3),
                             [(G_SALES, members(U1)), (G_OPS, members(U2, U3))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)

    def test_one_member_outside_every_group_is_unevaluated_never_false(self):
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), workforce(U1, U2, U3, U4),
                                [(G_STAFF, members(U1, U2, U3))])
        self.assert_unevaluated(res, info)
        cov = res["remoteAccessPoliciesGroupCoverage"]
        self.assertEqual((cov["membersTotal"], cov["membersCovered"], cov["uncoveredCount"]), (4, 3, 1))
        self.assertIn("1 of 4 enabled members are outside the included groups", info["dataCollection"]["errors"][0])
        self.assertFalse(info["evaluation"]["failReasons"][2:])

    def test_users_list_with_pages_left_is_unevaluated(self):
        users = workforce(U1, U2)
        users["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/users?$skiptoken=x"
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), users, [(G_STAFF, members(U1, U2))])
        self.assert_unevaluated(res, info)
        self.assertIn("enabled member account list could not be read whole", info["dataCollection"]["errors"][0])

    def test_member_list_with_pages_left_is_unevaluated(self):
        body = members(U1, U2)
        body["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/groups/x/transitiveMembers?$skiptoken=y"
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), workforce(U1, U2), [(G_STAFF, body)])
        self.assert_unevaluated(res, info)
        self.assertEqual(res["remoteAccessPoliciesGroupCoverage"]["groupsUnread"], [G_STAFF[:4]])
        self.assertIn("could not be read whole", info["dataCollection"]["errors"][0])

    def test_pagination_truncated_marker_is_unevaluated(self):
        users = workforce(U1, U2)
        users["paginationTruncated"] = True
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), users, [(G_STAFF, members(U1, U2))])
        self.assert_unevaluated(res, info)

    def test_count_that_disagrees_with_the_items_is_unevaluated(self):
        users = workforce(U1, U2)
        users["@odata.count"] = 3
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), users, [(G_STAFF, members(U1, U2))])
        self.assert_unevaluated(res, info)
        body = members(U1, U2)
        body["@odata.count"] = 5
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), workforce(U1, U2), [(G_STAFF, body)])
        self.assert_unevaluated(res, info)

    def test_lists_without_count_are_read_when_unpaged(self):
        res, _ = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), workforce(U1, U2, count=False),
                             [(G_STAFF, members(U1, U2, count=False))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)

    def test_error_bodies_are_unevaluated(self):
        denied = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges."}}
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), denied, [(G_STAFF, members(U1))])
        self.assert_unevaluated(res, info)
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), workforce(U1), [(G_STAFF, denied)])
        self.assert_unevaluated(res, info)

    def test_deleted_group_returned_as_vendor_error_is_unread(self):
        res, info = run_members(ca(gpolicy("MFA Standard users", [G_STAFF])), workforce(U1), [(G_STAFF, NOT_FOUND)])
        self.assert_unevaluated(res, info)
        self.assertEqual(res["remoteAccessPoliciesGroupCoverage"]["groupsUnread"], [G_STAFF[:4]])

    def test_unread_group_keeps_the_groups_that_were_read(self):
        # A second included group could not be read, but the first already holds every enabled member.
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF, G_OPS])), workforce(U1, U2),
                             [(G_STAFF, members(U1, U2)), (G_OPS, NOT_FOUND)])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertEqual(res["remoteAccessPoliciesGroupCoverage"]["groupsUnread"], [G_OPS[:4]])

    def test_excluded_users_are_allowed_and_counted(self):
        res, info = run_members(ca(gpolicy("MFA Staff", [G_STAFF], exclude_users=[U4])), workforce(U1, U2, U3, U4),
                                [(G_STAFF, members(U1, U2, U3))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        cov = res["remoteAccessPoliciesGroupCoverage"]
        self.assertEqual((cov["membersCovered"], cov["excludedCount"], cov["uncoveredCount"]), (3, 1, 0))
        self.assertIn("(1 excluded)", info["evaluation"]["passReasons"][1])

    def test_excluded_group_members_are_allowed(self):
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF], exclude=[G_BREAKGLASS])), workforce(U1, U2, U3),
                             [(G_STAFF, members(U1, U2)), (G_BREAKGLASS, members(U3))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertEqual(res["remoteAccessPoliciesGroupCoverage"]["excludedCount"], 1)

    def test_member_in_both_included_and_excluded_group_is_excluded_not_covered(self):
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF], exclude=[G_BREAKGLASS])), workforce(U1, U2),
                             [(G_STAFF, members(U1, U2)), (G_BREAKGLASS, members(U2))])
        cov = res["remoteAccessPoliciesGroupCoverage"]
        self.assertEqual((cov["membersCovered"], cov["excludedCount"]), (1, 1))

    def test_unread_excluded_group_makes_the_policy_count_for_nothing(self):
        res, info = run_members(ca(gpolicy("MFA Staff", [G_STAFF], exclude=[G_BREAKGLASS])), workforce(U1, U2),
                                [(G_STAFF, members(U1, U2)), (G_BREAKGLASS, NOT_FOUND)])
        self.assert_unevaluated(res, info)

    def test_included_user_ids_count(self):
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF], include_users=[U3])), workforce(U1, U2, U3),
                             [(G_STAFF, members(U1, U2))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)

    def test_nested_groups_count_through_the_transitive_read(self):
        # G_STAFF holds G_SALES; the transitive read lists G_SALES's users as members of G_STAFF.
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), workforce(U1, U2, U3),
                             [(G_STAFF, members(U1, U2, U3))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)

    def test_guests_and_disabled_accounts_are_not_the_workforce(self):
        extra = ({"id": GUEST, "accountEnabled": True, "userType": "Guest"},
                 {"id": DISABLED, "accountEnabled": False, "userType": "Member"})
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), workforce(U1, U2, extra=extra),
                             [(G_STAFF, members(U1, U2))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertEqual(res["remoteAccessPoliciesGroupCoverage"]["membersTotal"], 2)

    def test_user_item_without_enabled_or_type_is_unread(self):
        res, info = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), workforce(U1, extra=({"id": U2},)),
                                [(G_STAFF, members(U1, U2))])
        self.assert_unevaluated(res, info)

    def test_member_lists_that_cannot_be_paired_with_group_ids_read_nothing(self):
        out = m.transform({"conditionalAccessPolicies": ca(gpolicy("MFA Staff", [G_STAFF])), "groups": NAMED,
                           "workforceUsers": workforce(U1), "caPolicyGroups": {"groupIds": [{"id": G_STAFF}]},
                           "groupMembers": [members(U1), members(U1)]})
        self.assertIsNone(out["transformedResponse"]["isMFARequiredForRemoteAccess"])

    def test_group_id_read_twice_is_not_trusted(self):
        res, info = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), workforce(U1),
                                [(G_STAFF, members(U1)), (G_STAFF, members(U1))])
        self.assert_unevaluated(res, info)

    def test_group_not_in_the_read_list_is_unread(self):
        res, info = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), workforce(U1), [(G_OPS, members(U1))])
        self.assert_unevaluated(res, info)
        self.assertEqual(res["remoteAccessPoliciesGroupCoverage"]["groupsUnread"], [G_STAFF[:4]])

    def test_no_enabled_member_accounts_is_unevaluated(self):
        res, info = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), workforce(), [(G_STAFF, members())])
        self.assert_unevaluated(res, info)
        self.assertIn("no enabled member accounts were read", info["dataCollection"]["errors"][0])

    def test_group_policy_also_narrowed_by_client_type_platform_or_location_stays_partial(self):
        users, read = workforce(U1, U2), [(G_STAFF, members(U1, U2))]
        browser = gpolicy("MFA Staff browser", [G_STAFF], clients=["browser"])
        located = gpolicy("MFA Staff external", [G_STAFF], locations={"includeLocations": ["named-external"]})
        platform = gpolicy("MFA Staff Windows", [G_STAFF])
        platform["conditions"]["platforms"] = {"includePlatforms": ["windows"], "excludePlatforms": []}
        device = gpolicy("MFA Staff filtered devices", [G_STAFF])
        device["conditions"]["devices"] = {"deviceFilter": {"mode": "include", "rule": "device.isCompliant -eq True"}}
        for narrowed in (browser, located, platform, device):
            res, info = run_members(ca(narrowed), users, read)
            self.assert_unevaluated(res, info)
            self.assertNotIn("remoteAccessPoliciesGroupCoverage", res)

    def test_all_locations_excluding_trusted_still_counts(self):
        loc = {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}
        res, _ = run_members(ca(gpolicy("MFA Staff off-network", [G_STAFF], locations=loc)), workforce(U1),
                             [(G_STAFF, members(U1))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)

    def test_remote_desktop_app_policy_counts_for_rdp_only(self):
        rdp = gpolicy("MFA Staff Remote Desktop", [G_STAFF])
        rdp["conditions"]["applications"]["includeApplications"] = ["a4a365df-50f1-4397-bc59-1a1564b8bb9c"]
        res, info = run_members(ca(rdp), workforce(U1), [(G_STAFF, members(U1))])
        self.assertIs(res["isRDPProtected"], True)
        self.assertIs(res["isMFARequiredForRemoteAccess"], False)

    def test_role_scoped_policy_is_not_a_group_candidate(self):
        admins = gpolicy("MFA admins", [G_STAFF])
        admins["conditions"]["users"]["includeRoles"] = ["62e90394-69f5-4237-9190-012177145e10"]
        res, _ = run_members(ca(admins), workforce(U1), [(G_STAFF, members(U1))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], False)

    def test_report_only_group_policy_does_not_count(self):
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF], state="enabledForReportingButNotEnforced"),
                                policy("Block legacy auth", users=["All"], controls=("block",))),
                             workforce(U1), [(G_STAFF, members(U1))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], False)

    def test_all_users_policy_passes_whatever_the_membership_read(self):
        denied = {"error": {"code": "Authorization_RequestDenied"}}
        res, info = run_members(ca(policy("MFA everyone", users=["All"])), denied, [(G_STAFF, denied)])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)
        self.assertNotIn("remoteAccessPoliciesGroupCoverage", res)

    def test_none_empty_and_missing_membership_inputs_fail_closed(self):
        for users in (None, {}, [], "", {"value": None}):
            res, info = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), users, [(G_STAFF, members(U1))])
            self.assert_unevaluated(res, info)
        for body in (None, {}, [], "", "not json"):
            res, info = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), workforce(U1), [(G_STAFF, body)])
            self.assert_unevaluated(res, info)
        out = m.transform({"conditionalAccessPolicies": ca(gpolicy("MFA Staff", [G_STAFF])), "groups": NAMED,
                           "workforceUsers": workforce(U1)})
        self.assertIsNone(out["transformedResponse"]["isMFARequiredForRemoteAccess"])
        for holder in (None, {}, {"groupIds": None}, {"groupIds": "x"}, []):
            out = m.transform({"conditionalAccessPolicies": ca(gpolicy("MFA Staff", [G_STAFF])), "groups": NAMED,
                               "workforceUsers": workforce(U1), "caPolicyGroups": holder,
                               "groupMembers": [members(U1)]})
            self.assertIsNone(out["transformedResponse"]["isMFARequiredForRemoteAccess"])

    def test_without_a_membership_read_the_message_is_unchanged(self):
        res, info = run(ca(gpolicy("MFA Staff", [G_STAFF])), NAMED)
        self.assertIsNone(res["isMFARequiredForRemoteAccess"])
        self.assertNotIn("remoteAccessPoliciesGroupCoverage", res)
        self.assertTrue(info["dataCollection"]["errors"][0].endswith(
            "whether they reach every user and sign-in cannot be read here"))

    def test_page_list_of_users_is_read(self):
        page1 = {"@odata.context": USERS_CTX, "@odata.count": 2,
                 "value": [{"id": U1, "accountEnabled": True, "userType": "Member"}]}
        page2 = {"value": [{"id": U2, "accountEnabled": True, "userType": "Member"}]}
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF])), [page1, page2], [(G_STAFF, members(U1, U2))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)

    def test_ids_match_case_insensitively(self):
        res, _ = run_members(ca(gpolicy("MFA Staff", [G_STAFF.upper()])), workforce(U1.upper()),
                             [(G_STAFF, members(U1))])
        self.assertIs(res["isMFARequiredForRemoteAccess"], True)


if __name__ == "__main__":
    unittest.main()
