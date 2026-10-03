"""Duo isStrongAuthRequired from Policies v2 (GET /admin/v2/policies + /admin/v2/policies/summary).

Synthetic bodies in the documented shapes (Duo Admin API "Retrieve Policies", "Summarize Policies" and
"Policy Section Data"). Policy keys, app names and integration keys are invented. No customer data.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

KEY = "isStrongAuthRequired"
PR_ONLY = {"allowed_auth_list": ["webauthn-roaming", "webauthn-platform"],
           "blocked_auth_list": ["duo-push", "duo-push-pwl", "sms", "phonecall", "duo-passcode", "hardware-token",
                                 "desktop", "bypass", "bypass-pwl"],
           "require_verified_push": False}
# The documented defaults: blocked desktop, duo-passcode and phonecall; push and SMS allowed.
DOC_DEFAULT = {"allowed_auth_list": ["bypass", "bypass-pwl", "duo-push", "duo-push-pwl", "hardware-token", "sms",
                                     "webauthn-platform", "webauthn-platform-pwl", "webauthn-roaming",
                                     "webauthn-roaming-pwl"],
               "blocked_auth_list": ["desktop", "duo-passcode", "phonecall"], "require_verified_push": True}


def policy(key, name, methods=None, is_global=False, extra=None):
    sections = {}
    if methods is not None:
        sections["authentication_methods"] = copy.deepcopy(methods)
    sections.update(extra or {})
    return {"policy_key": key, "policy_name": name, "is_global_policy": is_global, "sections": sections}


GLOBAL_KEY = "POGLOBAL000000000001"
VPN_KEY = "POVPN000000000000001"
SPARE_KEY = "POSPARE00000000000001"


def bodies(global_methods, customs=(), applied=(), global_extra=None, truncated=False, count=None):
    """customs: [(key, name, methods, extra)]; applied: keys applied to an application."""
    pols = [policy(GLOBAL_KEY, "Global Policy", global_methods, True, global_extra)]
    for key, name, methods, extra in customs:
        pols.append(policy(key, name, methods, False, extra))
    summary = []
    for p in pols:
        applies = []
        if p["policy_key"] in applied:
            applies = [{"app_integration_key": "DIEXAMPLE00000000001", "app_name": "Example VPN", "apply_type": "app"}]
        summary.append({"policy_key": p["policy_key"], "policy_name": p["policy_name"],
                        "policy_applies_to": applies})
    return {"policies": {"response": pols},
            "summary": {"response": {"policies": summary, "policy_count": len(pols) if count is None else count,
                                     "response_is_truncated": truncated, "warnings": []}}}


def load():
    spec = importlib.util.spec_from_file_location("duo_strong_auth_pr",
                                                  Path(__file__).with_name("isStrongAuthRequiredByPolicy.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoStrongAuthPoliciesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def value(self, payload):
        out = self.t.transform(payload)
        return out["transformedResponse"][KEY], out

    # ---- True -------------------------------------------------------------------------------------
    def test_phishing_resistant_global_only_is_true(self):
        value, out = self.value(bodies(PR_ONLY))
        self.assertIs(value, True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_every_governing_policy_strong_is_true(self):
        customs = [(VPN_KEY, "VPN", PR_ONLY, None)]
        self.assertIs(self.value(bodies(PR_ONLY, customs, applied=[VPN_KEY]))[0], True)

    def test_custom_policy_without_methods_section_inherits_strong_global(self):
        customs = [(VPN_KEY, "VPN remembered devices", None, {"remembered_devices": {}})]
        self.assertIs(self.value(bodies(PR_ONLY, customs, applied=[VPN_KEY]))[0], True)

    def test_deny_all_counts_as_strong(self):
        customs = [(VPN_KEY, "Deny", DOC_DEFAULT, {"authentication_policy": {"user_auth_behavior": "deny"}})]
        self.assertIs(self.value(bodies(PR_ONLY, customs, applied=[VPN_KEY]))[0], True)

    def test_string_lists_and_string_booleans(self):
        b = bodies(PR_ONLY)
        m = b["policies"]["response"][0]["sections"]["authentication_methods"]
        m["allowed_auth_list"] = ", ".join(m["allowed_auth_list"])
        m["blocked_auth_list"] = ",".join(m["blocked_auth_list"])
        b["policies"]["response"][0]["is_global_policy"] = "True"
        b["summary"]["response"]["response_is_truncated"] = "False"
        self.assertIs(self.value(b)[0], True)

    def test_wrapped_and_json_string_inputs(self):
        for payload in ({"apiResponse": bodies(PR_ONLY)}, json.dumps(bodies(PR_ONLY)),
                        {"result": {"apiResponse": bodies(PR_ONLY)}}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertIs(self.value(payload)[0], True)

    # ---- False ------------------------------------------------------------------------------------
    def test_documented_default_policy_is_false(self):
        value, out = self.value(bodies(DOC_DEFAULT))
        self.assertIs(value, False)
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])

    def test_each_phishable_method_left_unblocked_is_false(self):
        for method in self.t.PHISHABLE:
            m = copy.deepcopy(PR_ONLY)
            m["blocked_auth_list"] = [x for x in m["blocked_auth_list"] if x != method]
            with self.subTest(method=method):
                self.assertIs(self.value(bodies(m))[0], False)

    def test_unlisted_method_is_allowed_per_docs(self):
        m = {"allowed_auth_list": ["webauthn-roaming"], "blocked_auth_list": ["desktop", "duo-passcode", "phonecall"]}
        self.assertIs(self.value(bodies(m))[0], False)

    def test_all_governing_weak_is_false(self):
        customs = [(VPN_KEY, "VPN", DOC_DEFAULT, None)]
        self.assertIs(self.value(bodies(DOC_DEFAULT, customs, applied=[VPN_KEY]))[0], False)

    def test_unapplied_strong_policy_does_not_rescue_a_weak_global(self):
        customs = [(SPARE_KEY, "Unused strong", PR_ONLY, None)]
        self.assertIs(self.value(bodies(DOC_DEFAULT, customs, applied=[]))[0], False)

    def test_bypass_and_no_mfa_new_users_are_weak(self):
        for extra in ({"authentication_policy": {"user_auth_behavior": "bypass"}},
                      {"new_user": {"new_user_behavior": "no-mfa"}}):
            with self.subTest(extra=extra):
                self.assertIs(self.value(bodies(PR_ONLY, global_extra=extra))[0], False)

    # ---- Not evaluated ----------------------------------------------------------------------------
    def test_mixed_policies_are_not_evaluated(self):
        customs = [(VPN_KEY, "VPN", PR_ONLY, None)]
        value, out = self.value(bodies(DOC_DEFAULT, customs, applied=[VPN_KEY]))
        self.assertIsNone(value)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        customs = [(VPN_KEY, "VPN", DOC_DEFAULT, None)]
        self.assertIsNone(self.value(bodies(PR_ONLY, customs, applied=[VPN_KEY]))[0])

    def test_unknown_method_is_not_evaluated(self):
        m = copy.deepcopy(PR_ONLY)
        m["allowed_auth_list"] = m["allowed_auth_list"] + ["future-method"]
        self.assertIsNone(self.value(bodies(m))[0])

    def test_error_bodies_are_not_evaluated(self):
        errors = [
            {"stat": "FAIL", "code": 40103, "message": "Invalid signature in request credentials"},
            {"stat": "FAIL", "code": 40301, "message": "Access forbidden"},
            {"error": True, "errorType": "authentication", "statusCode": 401, "message": "Authentication Failed"},
            {"statusCode": 403, "message": "Forbidden"},
        ]
        for err in errors:
            for part in ("policies", "summary"):
                b = bodies(PR_ONLY)
                b[part] = err
                with self.subTest(part=part, err=err.get("code") or err.get("statusCode")):
                    self.assertIsNone(self.value(b)[0])
            with self.subTest(whole=str(err)[:30]):
                self.assertIsNone(self.value(err)[0])

    def test_no_evidence_inputs_are_not_evaluated(self):
        for payload in ({}, None, [], "", "{}", {"policies": {"response": []}, "summary": {"response": {}}},
                        {"policies": {"response": []}}, {"summary": bodies(PR_ONLY)["summary"]},
                        {"policies": {"response": []}, "summary": {"response": {"policies": [], "policy_count": 0,
                                                                                "response_is_truncated": False}}}):
            with self.subTest(payload=str(payload)[:50]):
                self.assertIsNone(self.value(payload)[0])

    def test_truncated_or_miscounted_summary_is_not_evaluated(self):
        self.assertIsNone(self.value(bodies(PR_ONLY, truncated=True))[0])
        self.assertIsNone(self.value(bodies(PR_ONLY, count=7))[0])
        b = bodies(PR_ONLY)
        del b["summary"]["response"]["response_is_truncated"]
        self.assertIsNone(self.value(b)[0])

    def test_global_without_methods_section_is_not_evaluated(self):
        self.assertIsNone(self.value(bodies(None))[0])

    def test_no_or_two_global_policies_are_not_evaluated(self):
        b = bodies(PR_ONLY)
        b["policies"]["response"][0]["is_global_policy"] = False
        self.assertIsNone(self.value(b)[0])
        b = bodies(PR_ONLY, [(VPN_KEY, "VPN", PR_ONLY, None)], applied=[VPN_KEY])
        b["policies"]["response"][1]["is_global_policy"] = True
        self.assertIsNone(self.value(b)[0])


if __name__ == "__main__":
    unittest.main()
