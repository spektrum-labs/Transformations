"""Unit tests for four Entra ID transforms added 2026-09-29:
isConditionalAccessEnabled, isSessionTimeoutConfigured, isMFAEnforcedForAdmins, isSSOEnabled.

Fixtures follow the documented Graph shapes (conditionalAccessPolicy, identitySecurityDefaultsEnforcementPolicy,
servicePrincipal). The report-only fixture mirrors a real tenant read of 2026-09-29 (names and ids replaced):
five policies, every one in state enabledForReportingButNotEnforced.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CA = load("isconditionalaccessenabled")
ST = load("issessiontimeoutconfigured")
MFA = load("ismfaenforcedforadmins")
SSO = load("isssoenabled")

CTX = "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies"
GA = "62e90394-69f5-4237-9190-012177145e10"
SEC = "194ae4cb-b126-40b2-bd5b-6091b380977d"


def policy(state="enabled", users=None, roles=None, exclude_roles=None, apps=None, grant=None, strength=None,
           session=None, name="p"):
    return {
        "id": name, "displayName": name, "state": state,
        "conditions": {"users": {"includeUsers": users if users is not None else ["All"], "excludeUsers": ["breakglass"],
                                 "includeRoles": roles or [], "excludeRoles": exclude_roles or []},
                       "applications": {"includeApplications": apps if apps is not None else ["All"]}},
        "grantControls": None if grant is None and strength is None else
        {"operator": "OR", "builtInControls": grant or [], "authenticationStrength": strength},
        "sessionControls": session,
    }


def collection(policies, next_link=False):
    body = {"@odata.context": CTX, "value": policies}
    if next_link:
        body["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=x"
    return body


REPORT_ONLY = collection([
    policy("enabledForReportingButNotEnforced", grant=["block"], name="Block legacy"),
    policy("enabledForReportingButNotEnforced", grant=["mfa"], name="MFA all users"),
    policy("enabledForReportingButNotEnforced", users=["None"], apps=["None"], grant=["block"], name="Template"),
    policy("enabledForReportingButNotEnforced", grant=["mfa"], name="MFA admins"),
    policy("enabledForReportingButNotEnforced", grant=["block"], name="Block countries"),
])

NO_EVIDENCE = [None, {}, [], "", {"value": []}, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
               {"status_code": 403, "error": True, "message": "Forbidden"}, {"unrelated": {"value": 1}}]


def val(module, body, key):
    return module.transform(body)["transformedResponse"][key]


def status(module, body):
    return module.transform(body)["additionalInfo"]["dataCollection"]["status"]


class ConditionalAccessEnabled(unittest.TestCase):
    def test_report_only_is_false(self):
        out = CA.transform(REPORT_ONLY)["transformedResponse"]
        self.assertIs(out["isConditionalAccessEnabled"], False)
        self.assertEqual(out["reportOnlyPolicyCount"], 5)
        self.assertEqual(out["enforcedPolicyCount"], 0)

    def test_one_enforced_policy_is_true(self):
        body = copy.deepcopy(REPORT_ONLY)
        body["value"][1]["state"] = "enabled"
        self.assertIs(val(CA, body, "isConditionalAccessEnabled"), True)
        self.assertEqual(val(CA, body, "enforcedPolicyCount"), 1)

    def test_enabled_policy_with_no_controls_does_not_count(self):
        self.assertIs(val(CA, collection([policy("enabled")]), "isConditionalAccessEnabled"), False)

    def test_session_control_counts(self):
        body = collection([policy("enabled", session={"signInFrequency": {"isEnabled": True, "value": 8, "type": "hours"}})])
        self.assertIs(val(CA, body, "isConditionalAccessEnabled"), True)

    def test_empty_complete_list_is_false(self):
        self.assertIs(val(CA, collection([]), "isConditionalAccessEnabled"), False)

    def test_partial_page_without_enforced_is_none(self):
        self.assertIsNone(val(CA, collection([policy("disabled", grant=["mfa"])], next_link=True), "isConditionalAccessEnabled"))

    def test_no_evidence_is_none(self):
        for body in NO_EVIDENCE:
            self.assertIsNone(val(CA, body, "isConditionalAccessEnabled"), body)
            self.assertEqual(status(CA, body), "error", body)

    def test_wrapped_and_string_inputs(self):
        body = collection([policy("enabled", grant=["mfa"])])
        self.assertIs(val(CA, {"apiResponse": body}, "isConditionalAccessEnabled"), True)
        self.assertIs(val(CA, {"data": body, "validation": {"status": "success"}}, "isConditionalAccessEnabled"), True)
        self.assertIs(val(CA, json.dumps(body), "isConditionalAccessEnabled"), True)


class SessionTimeout(unittest.TestCase):
    def freq(self, value, unit, interval="timeBased", state="enabled", users=None, apps=None):
        return policy(state, users=users, apps=apps, session={"signInFrequency": {
            "isEnabled": True, "value": value, "type": unit, "frequencyInterval": interval,
            "authenticationType": "primaryAndSecondaryAuthentication"}})

    def test_hours_to_minutes(self):
        self.assertEqual(val(ST, collection([self.freq(8, "hours")]), "isSessionTimeoutConfigured"), 480)

    def test_days_and_minimum(self):
        body = collection([self.freq(1, "days"), self.freq(4, "hours")])
        self.assertEqual(val(ST, body, "isSessionTimeoutConfigured"), 240)

    def test_every_time_is_zero(self):
        self.assertEqual(val(ST, collection([self.freq(None, None, "everyTime")]), "isSessionTimeoutConfigured"), 0)

    def test_scoped_or_report_only_policies_do_not_count(self):
        body = collection([self.freq(1, "hours", state="enabledForReportingButNotEnforced"),
                           self.freq(1, "hours", users=["group-only"]), self.freq(1, "hours", apps=["app-id"])])
        out = ST.transform(body)["transformedResponse"]
        self.assertEqual(out["isSessionTimeoutConfigured"], 129600)
        self.assertIs(out["usingDefault"], True)

    def test_report_only_tenant_gets_default(self):
        self.assertEqual(val(ST, REPORT_ONLY, "isSessionTimeoutConfigured"), 129600)

    def test_unreadable_frequency_is_none(self):
        self.assertIsNone(val(ST, collection([self.freq("8", "hours")]), "isSessionTimeoutConfigured"))

    def test_partial_page_without_policy_is_none(self):
        self.assertIsNone(val(ST, collection([], next_link=True), "isSessionTimeoutConfigured"))

    def test_no_evidence_is_none(self):
        for body in NO_EVIDENCE:
            self.assertIsNone(val(ST, body, "isSessionTimeoutConfigured"), body)
            self.assertEqual(status(ST, body), "error", body)


class MfaForAdmins(unittest.TestCase):
    def merged(self, policies, defaults=False, next_link=False):
        return {"conditionalAccessPolicies": collection(policies, next_link),
                "securityDefaults": {"id": "00000000-0000-0000-0000-000000000005", "isEnabled": defaults}}

    def test_report_only_without_defaults_is_false(self):
        out = MFA.transform(self.merged(REPORT_ONLY["value"]))["transformedResponse"]
        self.assertIs(out["isMFAEnforcedForAdmins"], False)
        self.assertEqual(out["adminRolesCovered"], 0)

    def test_security_defaults_is_true(self):
        out = MFA.transform(self.merged(REPORT_ONLY["value"], defaults=True))["transformedResponse"]
        self.assertIs(out["isMFAEnforcedForAdmins"], True)
        self.assertEqual(out["adminMfaRoleCoveragePercentage"], 100)

    def test_all_users_mfa_policy_is_true(self):
        self.assertIs(val(MFA, self.merged([policy(grant=["mfa"])]), "isMFAEnforcedForAdmins"), True)

    def test_authentication_strength_counts(self):
        body = self.merged([policy(strength={"id": "00000000-0000-0000-0000-000000000004", "displayName": "Phishing-resistant MFA"})])
        self.assertIs(val(MFA, body, "isMFAEnforcedForAdmins"), True)

    def test_admin_portals_app_counts(self):
        self.assertIs(val(MFA, self.merged([policy(apps=["MicrosoftAdminPortals"], grant=["mfa"])]), "isMFAEnforcedForAdmins"), True)

    def test_partial_role_coverage_is_false_with_count(self):
        out = MFA.transform(self.merged([policy(users=[], roles=[GA, SEC], grant=["mfa"])]))["transformedResponse"]
        self.assertIs(out["isMFAEnforcedForAdmins"], False)
        self.assertEqual(out["adminRolesCovered"], 2)
        self.assertEqual(out["adminMfaRoleCoveragePercentage"], 14)

    def test_excluded_role_is_not_covered(self):
        self.assertIs(val(MFA, self.merged([policy(exclude_roles=[GA], grant=["mfa"])]), "isMFAEnforcedForAdmins"), False)

    def test_block_only_or_scoped_app_does_not_count(self):
        body = self.merged([policy(grant=["block"]), policy(apps=["some-app"], grant=["mfa"])])
        self.assertIs(val(MFA, body, "isMFAEnforcedForAdmins"), False)

    def test_partial_page_not_fully_covered_is_none(self):
        self.assertIsNone(val(MFA, self.merged([], next_link=True), "isMFAEnforcedForAdmins"))

    def test_missing_security_defaults_is_none(self):
        self.assertIsNone(val(MFA, {"conditionalAccessPolicies": collection([policy(grant=["mfa"])])}, "isMFAEnforcedForAdmins"))
        self.assertIsNone(val(MFA, {"conditionalAccessPolicies": collection([policy(grant=["mfa"])]),
                                    "securityDefaults": {"isEnabled": "true"}}, "isMFAEnforcedForAdmins"))

    def test_bare_policy_list_is_none(self):
        self.assertIsNone(val(MFA, collection([policy(grant=["mfa"])]), "isMFAEnforcedForAdmins"))

    def test_no_evidence_is_none(self):
        for body in NO_EVIDENCE:
            self.assertIsNone(val(MFA, body, "isMFAEnforcedForAdmins"), body)
            self.assertEqual(status(MFA, body), "error", body)


class SingleSignOn(unittest.TestCase):
    def sps(self, modes, next_link=False, disabled=()):
        body = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#servicePrincipals",
                "value": [{"id": "sp" + str(i), "appId": "a" + str(i), "appDisplayName": "App " + str(i),
                           "accountEnabled": i not in disabled, "servicePrincipalType": "Application",
                           "preferredSingleSignOnMode": m} for i, m in enumerate(modes)]}
        if next_link:
            body["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=x"
        return body

    def test_saml_app_is_true(self):
        out = SSO.transform(self.sps([None, None, "saml", "password"]))["transformedResponse"]
        self.assertIs(out["isSSOEnabled"], True)
        self.assertEqual(out["ssoApplicationCount"], 1)
        self.assertEqual(out["passwordSsoApplicationCount"], 1)

    def test_oidc_app_is_true(self):
        self.assertIs(val(SSO, self.sps([None, "oidc"]), "isSSOEnabled"), True)

    def test_only_password_or_none_is_false(self):
        self.assertIs(val(SSO, self.sps([None, "password", "notSupported"]), "isSSOEnabled"), False)

    def test_disabled_saml_app_does_not_count(self):
        self.assertIs(val(SSO, self.sps([None, "saml"], disabled=(1,)), "isSSOEnabled"), False)

    def test_partial_page_without_sso_is_none(self):
        self.assertIsNone(val(SSO, self.sps([None, None], next_link=True), "isSSOEnabled"))

    def test_partial_page_with_sso_is_true(self):
        self.assertIs(val(SSO, self.sps([None, "saml"], next_link=True), "isSSOEnabled"), True)

    def test_no_evidence_is_none(self):
        for body in NO_EVIDENCE:
            self.assertIsNone(val(SSO, body, "isSSOEnabled"), body)
            self.assertEqual(status(SSO, body), "error", body)


if __name__ == "__main__":
    unittest.main()
