"""isMFARequiredForRemoteAccess reads apps, ACCESS_POLICY policies and their rules from
getRemoteAccessMfaPolicies (listApplications + getAccessPolicy + listPolicyRules).

Fixture shape mirrors a real Identity Engine read (ids, labels and domains replaced): two AWS Client
VPN catalog apps share one authentication policy whose only rule is an ACTIVE ALLOW, ASSURANCE / 2FA
catch-all; other apps use other policies.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("ismfarequiredforremoteaccess.py")
KEY = "isMFARequiredForRemoteAccess"
BASE = "https://example.okta.com/api/v1/policies/"


def load():
    spec = importlib.util.spec_from_file_location("ismfarequiredforremoteaccess", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rule(name, mode="2FA", access="ALLOW", status="ACTIVE", kind="ASSURANCE"):
    return {"name": name, "status": status,
            "actions": {"appSignOn": {"access": access, "verificationMethod": {"type": kind, "factorMode": mode}}}}


def app(app_id, name, label, policy, mode="SAML_2_0", status="ACTIVE", sign_on=None):
    body = {"id": app_id, "name": name, "label": label, "status": status, "signOnMode": mode,
            "settings": {"signOn": sign_on or {"audienceOverride": None, "ssoAcsUrlOverride": None}},
            "_links": {}}
    if policy:
        body["_links"]["accessPolicy"] = {"href": BASE + policy}
    return body


REAL = {"result": {
    "applications": [
        app("0oa1", "aws_clientvpn", "VPN Production", "rstVPN"),
        app("0oa2", "aws_clientvpn", "VPN Development", "rstVPN"),
        app("0oa3", "slack", "Chat", "rstVPN"),
        app("0oa4", "mfa_rdp", "RDP MFA", None, mode="MFA_AS_SERVICE"),
        app("0oa5", "github", "Code", "rstOther"),
    ],
    "paginationStats": {"applications": {"paginationTruncated": False}},
    "accessPolicies": [
        {"id": "rstAdmin", "name": "Okta Admin Console", "status": "ACTIVE"},
        {"id": "rstVPN", "name": "Any two factors", "status": "ACTIVE"},
        {"id": "rstOther", "name": "Other", "status": "ACTIVE"},
    ],
    "accessRules": [
        [rule("Admin App Policy")],
        [rule("Catch-all Rule")],
        [rule("Password only", mode="1FA")],
    ],
}}


class RemoteAccessMfaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, payload):
        return self.t.transform(payload)

    def out(self, payload):
        return self.run_t(payload)["transformedResponse"]

    def assert_not_evaluated(self, payload):
        result = self.run_t(payload)
        self.assertIsNone(result["transformedResponse"][KEY])
        self.assertEqual(result["additionalInfo"]["dataCollection"]["status"], "error")

    def test_real_shape_passes_with_counts(self):
        out = self.out(REAL)
        self.assertIs(out[KEY], True)
        self.assertEqual(out["remoteAccessApps"], 2)
        self.assertEqual(out["remoteAccessAppsWithoutMFA"], 0)

    def test_json_string_input(self):
        self.assertIs(self.out(json.dumps(REAL))[KEY], True)

    def test_single_factor_rule_on_vpn_policy_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][1].insert(0, rule("Office network", mode="1FA"))
        out = self.out(flipped)
        self.assertIs(out[KEY], False)
        self.assertEqual(out["remoteAccessAppsWithoutMFA"], 2)

    def test_two_fa_if_possible_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][1] = [rule("Catch-all Rule", mode="2FA_If_Possible")]
        self.assertIs(self.out(flipped)[KEY], False)

    def test_unknown_verification_method_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][1] = [rule("Chain", kind="AUTH_METHOD_CHAIN", mode="")]
        self.assertIs(self.out(flipped)[KEY], False)

    def test_one_vpn_app_on_weak_policy_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["applications"][1]["_links"]["accessPolicy"]["href"] = BASE + "rstOther"
        out = self.out(flipped)
        self.assertIs(out[KEY], False)
        self.assertEqual(out["remoteAccessAppsWithoutMFA"], 1)

    def test_deny_and_inactive_rules_are_not_judged(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][1].append(rule("Blocked", mode="1FA", access="DENY"))
        flipped["result"]["accessRules"][1].append(rule("Old", mode="1FA", status="INACTIVE"))
        self.assertIs(self.out(flipped)[KEY], True)

    def test_weak_policy_on_non_remote_app_does_not_count(self):
        # rstOther is single-factor but only fronts a non-remote-access app.
        self.assertIs(self.out(REAL)[KEY], True)

    def test_label_alone_does_not_make_an_app_remote_access(self):
        flipped = copy.deepcopy(REAL)
        for item in flipped["result"]["applications"][:2]:
            item["name"] = "custom_saml"
        flipped["result"]["applications"][4]["label"] = "AWS Client VPN"
        self.assert_not_evaluated(flipped)

    def test_custom_saml_app_identified_by_client_vpn_audience(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["applications"] = [
            app("0oa9", "custom_saml_1", "Anything", "rstVPN",
                sign_on={"audience": "urn:amazon:webservices:clientvpn", "ssoAcsUrl": "http://127.0.0.1:35001"}),
        ]
        out = self.out(flipped)
        self.assertIs(out[KEY], True)
        self.assertEqual(out["remoteAccessApps"], 1)

    def test_custom_saml_app_identified_by_self_service_acs(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["applications"] = [
            app("0oa9", "custom_saml_1", "Anything", "rstOther",
                sign_on={"ssoAcsUrl": "https://self-service.clientvpn.amazonaws.com/api/auth/sso/saml"}),
        ]
        self.assertIs(self.out(flipped)[KEY], False)

    def test_no_remote_access_app_is_not_evaluated(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["applications"] = flipped["result"]["applications"][2:]
        self.assert_not_evaluated(flipped)

    def test_inactive_remote_access_app_is_not_judged(self):
        flipped = copy.deepcopy(REAL)
        for item in flipped["result"]["applications"][:2]:
            item["status"] = "INACTIVE"
        self.assert_not_evaluated(flipped)

    def test_missing_policy_link_is_not_evaluated(self):
        flipped = copy.deepcopy(REAL)
        del flipped["result"]["applications"][0]["_links"]["accessPolicy"]
        self.assert_not_evaluated(flipped)

    def test_policy_not_returned_is_not_evaluated(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessPolicies"][1]["id"] = "rstGone"
        self.assert_not_evaluated(flipped)

    def test_measured_weak_app_beats_unmeasured_app(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["applications"][0]["_links"]["accessPolicy"]["href"] = BASE + "rstOther"
        del flipped["result"]["applications"][1]["_links"]["accessPolicy"]
        self.assertIs(self.out(flipped)[KEY], False)

    def test_inactive_policy_is_not_evaluated(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessPolicies"][1]["status"] = "INACTIVE"
        self.assert_not_evaluated(flipped)

    def test_policy_with_no_allow_rule_is_not_evaluated(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][1] = [rule("Catch-all Rule", access="DENY")]
        self.assert_not_evaluated(flipped)

    def test_wrapped_rule_lists_are_read(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"] = [{"apiResponse": rules} for rules in flipped["result"]["accessRules"]]
        self.assertIs(self.out(flipped)[KEY], True)

    def test_truncated_app_list_is_not_evaluated(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["paginationTruncated"] = True
        self.assert_not_evaluated(flipped)

    def test_misaligned_rule_lists_are_not_evaluated(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"] = flipped["result"]["accessRules"][:2]
        self.assert_not_evaluated(flipped)

    def test_empty_and_error_bodies_are_not_evaluated(self):
        for body in [{}, None, "{}", {"result": {}}, {"applications": [], "accessPolicies": [], "accessRules": []},
                     {"errorCode": "E0000006", "errorSummary": "You do not have permission"},
                     {"statusCode": 401, "error": "Unauthorized"}, b"not json"]:
            with self.subTest(body=body):
                self.assert_not_evaluated(body)


if __name__ == "__main__":
    unittest.main()
