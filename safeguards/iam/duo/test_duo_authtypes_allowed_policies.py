"""Duo authTypesAllowed ("no weak factors") from Policies v2 (GET /admin/v2/policies + /admin/v2/policies/summary).

Synthetic bodies in the documented shapes (Duo Admin API "Retrieve Policies", "Summarize Policies" and "Policy
Section Data"). Policy keys, names and app keys are invented. No customer data.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent
KEY = "authTypesAllowed"
RESULT_KEYS = ["authTypesAllowed", "weakAuthMethodsAllowed", "strongAuthMethodsAllowed", "governingPolicies",
               "policiesAllowingWeakMethods"]
ALL_WEAK_BLOCKED = {"allowed_auth_list": ["duo-push", "duo-passcode", "webauthn-platform", "webauthn-roaming"],
                    "blocked_auth_list": ["sms", "phonecall", "bypass", "bypass-pwl"], "require_verified_push": True}
# Duo's documented defaults: blocked desktop, duo-passcode and phonecall; SMS and bypass codes allowed.
DOC_DEFAULT = {"allowed_auth_list": ["bypass", "bypass-pwl", "duo-push", "duo-push-pwl", "hardware-token", "sms",
                                     "webauthn-platform", "webauthn-platform-pwl", "webauthn-roaming",
                                     "webauthn-roaming-pwl"],
               "blocked_auth_list": ["desktop", "duo-passcode", "phonecall"], "require_verified_push": True}
GLOBAL_KEY = "POGLOBAL000000000001"


def methods(blocked, allowed=None):
    return {"allowed_auth_list": list(allowed or []), "blocked_auth_list": list(blocked)}


def policy(key, name, meth=None, is_global=False, extra=None):
    sections = {}
    if meth is not None:
        sections["authentication_methods"] = copy.deepcopy(meth)
    sections.update(extra or {})
    return {"policy_key": key, "policy_name": name, "is_global_policy": is_global, "sections": sections}


def bodies(global_methods, customs=(), applied=(), global_extra=None, truncated=False, count=None):
    """customs: [(key, name, methods, extra)]; applied: custom keys applied to an application."""
    pols = [policy(GLOBAL_KEY, "Global Policy", global_methods, True, global_extra)]
    for key, name, meth, extra in customs:
        pols.append(policy(key, name, meth, False, extra))
    summary = []
    for p in pols:
        applies = []
        if p["policy_key"] in applied:
            applies = [{"app_integration_key": "DIEXAMPLE00000000001", "app_name": "Example App", "apply_type": "app"}]
        summary.append({"policy_key": p["policy_key"], "policy_name": p["policy_name"], "policy_applies_to": applies})
    return {"policies": {"stat": "OK", "response": pols},
            "summary": {"stat": "OK", "response": {"policies": summary,
                                                   "policy_count": len(pols) if count is None else count,
                                                   "response_is_truncated": truncated, "warnings": []}}}


def load():
    spec = importlib.util.spec_from_file_location("duo_authtypes_policies", HERE / "authTypesAllowed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoAuthTypesAllowedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def value(self, payload):
        return self.t.transform(payload)["transformedResponse"][KEY]

    def assert_unevaluated(self, out):
        result = out["transformedResponse"]
        self.assertEqual(sorted(result), sorted(RESULT_KEYS))
        for k in result:
            self.assertIsNone(result[k], k)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    # ---- PASS: only strong factors -------------------------------------------------------------
    def test_only_strong_methods_pass(self):
        out = self.t.transform(bodies(ALL_WEAK_BLOCKED))
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["transformedResponse"]["weakAuthMethodsAllowed"], [])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_totp_and_hardware_tokens_are_strong(self):
        # Duo Mobile passcodes and OTP hardware tokens count as strong, as Entra (software/hardware OATH) and
        # Okta (google_otp) count them.
        meth = methods(["sms", "phonecall", "bypass", "bypass-pwl"], ["duo-passcode", "hardware-token"])
        self.assertIs(self.value(bodies(meth)), True)

    def test_phishing_resistant_only_passes(self):
        meth = methods(["sms", "phonecall", "bypass", "bypass-pwl", "duo-push", "duo-push-pwl", "duo-passcode",
                        "hardware-token", "desktop"], ["webauthn-roaming", "webauthn-platform"])
        self.assertIs(self.value(bodies(meth)), True)

    def test_custom_policy_without_section_inherits_strong_global(self):
        body = bodies(ALL_WEAK_BLOCKED, [("POC1", "Custom", None, None)], applied=["POC1"])
        self.assertIs(self.value(body), True)

    def test_unapplied_weak_custom_policy_governs_nothing(self):
        body = bodies(ALL_WEAK_BLOCKED, [("POC1", "Unused", DOC_DEFAULT, None)], applied=[])
        self.assertIs(self.value(body), True)

    def test_method_lists_as_comma_separated_strings(self):
        meth = {"allowed_auth_list": "duo-push, webauthn-roaming", "blocked_auth_list": "sms,phonecall,bypass,bypass-pwl"}
        self.assertIs(self.value(bodies(meth)), True)

    def test_string_booleans_and_wrappers(self):
        body = bodies(ALL_WEAK_BLOCKED)
        body["summary"]["response"]["response_is_truncated"] = "False"
        body["policies"]["response"][0]["is_global_policy"] = "true"
        for wrapped in (body, json.dumps(body), json.dumps(body).encode("utf-8"), {"apiResponse": body}):
            with self.subTest(kind=type(wrapped).__name__):
                self.assertIs(self.value(wrapped), True)

    # ---- FAIL: any weak factor -------------------------------------------------------------------
    def test_documented_defaults_fail(self):
        out = self.t.transform(bodies(DOC_DEFAULT))
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertEqual(out["transformedResponse"]["weakAuthMethodsAllowed"], ["sms", "bypass", "bypass-pwl"])
        self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])

    def test_each_weak_method_alone_fails(self):
        for weak in ["sms", "phonecall", "bypass", "bypass-pwl"]:
            blocked = [m for m in ["sms", "phonecall", "bypass", "bypass-pwl"] if m != weak]
            with self.subTest(weak=weak):
                out = self.t.transform(bodies(methods(blocked, ["duo-push", "webauthn-roaming"])))
                self.assertIs(out["transformedResponse"][KEY], False)
                self.assertEqual(out["transformedResponse"]["weakAuthMethodsAllowed"], [weak])

    def test_weak_method_permitted_because_not_blocked(self):
        # Not in allowed_auth_list, but "not included in blocked_auth_list is allowed".
        meth = methods(["sms", "bypass", "bypass-pwl"], ["duo-push"])
        out = self.t.transform(bodies(meth))
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertEqual(out["transformedResponse"]["weakAuthMethodsAllowed"], ["phonecall"])

    def test_push_present_with_sms_on_fails(self):
        # The old settings-based rule passed this ("at least one strong factor").
        meth = methods(["phonecall", "bypass", "bypass-pwl"], ["duo-push", "sms"])
        self.assertIs(self.value(bodies(meth)), False)

    def test_applied_custom_policy_with_weak_methods_fails(self):
        body = bodies(ALL_WEAK_BLOCKED, [("POC1", "Legacy apps", DOC_DEFAULT, None)], applied=["POC1"])
        out = self.t.transform(body)
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertEqual(out["transformedResponse"]["policiesAllowingWeakMethods"], 1)
        self.assertIn("Legacy apps", " ".join(out["additionalInfo"]["evaluation"]["failReasons"]))

    def test_weak_global_fails_even_with_strong_custom(self):
        body = bodies(DOC_DEFAULT, [("POC1", "Strict", ALL_WEAK_BLOCKED, None)], applied=["POC1"])
        self.assertIs(self.value(body), False)

    def test_weak_and_unknown_is_still_false(self):
        meth = methods(["phonecall", "bypass", "bypass-pwl"], ["sms", "brand-new-method"])
        self.assertIs(self.value(bodies(meth)), False)

    def test_fixture_returns_false(self):
        payload = json.loads((HERE / "fixtures" / "duo_policies_v2_weak_synthetic.json").read_text())
        self.assertIs(self.value(payload), False)

    def test_fixture_returns_true(self):
        payload = json.loads((HERE / "fixtures" / "duo_policies_v2_strong_synthetic.json").read_text())
        self.assertIs(self.value(payload), True)

    def test_mfa_bypass_behaviour_is_a_finding_not_the_verdict(self):
        extra = {"authentication_policy": {"user_auth_behavior": "bypass"}, "new_user": {"new_user_behavior": "no-mfa"}}
        out = self.t.transform(bodies(ALL_WEAK_BLOCKED, global_extra=extra))
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(len(out["additionalInfo"]["evaluation"]["additionalFindings"]), 2)

    # ---- None: missing or partial ------------------------------------------------------------------
    def test_nothing_measured_is_unevaluated(self):
        for payload in [{}, "", b"", None, [], 42, "{bad json", b"\xff\xfe", "{}", "[]", "null",
                        {"stat": "FAIL", "code": 40002, "message": "Invalid request parameters"},
                        {"error": "boom"}, {"statusCode": 500, "body": "oops"},
                        {"response": {}}, {"policies": None, "summary": None}]:
            with self.subTest(payload=str(payload)[:60]):
                self.assert_unevaluated(self.t.transform(payload))

    def test_settings_body_is_unevaluated(self):
        # /admin/v1/settings push/sms/voice/mobile_otp flags are legacy and always false.
        for payload in [{"stat": "OK", "response": {"push_enabled": True, "sms_enabled": True}},
                        {"push_enabled": False, "sms_enabled": False, "voice_enabled": False,
                         "mobile_otp_enabled": False}]:
            with self.subTest(payload=str(payload)[:60]):
                out = self.t.transform(payload)
                self.assert_unevaluated(out)
                self.assertIn("legacy", " ".join(out["additionalInfo"]["dataCollection"]["errors"]))

    def test_vendor_refusal_marker(self):
        forbidden = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden",
                                               "body": {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}}}
        for payload in [forbidden, {"policies": forbidden, "summary": bodies(ALL_WEAK_BLOCKED)["summary"]},
                        {"policies": bodies(ALL_WEAK_BLOCKED)["policies"], "summary": forbidden}]:
            with self.subTest(payload=str(payload)[:60]):
                out = self.t.transform(payload)
                self.assert_unevaluated(out)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["errorCode"], "permission_not_granted")
        out = self.t.transform({"vendorErrorAsResponse": {"status": 500}})
        self.assert_unevaluated(out)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["errorCode"], "vendor_refusal")

    def test_error_bodies_in_either_read(self):
        good = bodies(ALL_WEAK_BLOCKED)
        for which in ["policies", "summary"]:
            for err in [{"stat": "FAIL", "code": 40301, "message": "Access forbidden"},
                        {"stat": "FAIL", "code": 40103, "message": "Invalid signature"},
                        {"error": "timeout"}, {"statusCode": 401}]:
                body = copy.deepcopy(good)
                body[which] = err
                with self.subTest(which=which, err=str(err)[:40]):
                    self.assert_unevaluated(self.t.transform(body))

    def test_missing_one_read(self):
        good = bodies(ALL_WEAK_BLOCKED)
        self.assert_unevaluated(self.t.transform({"policies": good["policies"]}))
        self.assert_unevaluated(self.t.transform({"summary": good["summary"]}))

    def test_truncated_or_partial_summary(self):
        body = bodies(ALL_WEAK_BLOCKED)
        for mutate in [lambda b: b["summary"]["response"].update(response_is_truncated=True),
                       lambda b: b["summary"]["response"].pop("response_is_truncated"),
                       lambda b: b["summary"]["response"].update(response_is_truncated="maybe"),
                       lambda b: b["summary"]["response"].update(policy_count=7),
                       lambda b: b["summary"]["response"].pop("policy_count"),
                       lambda b: b["summary"]["response"].update(policies="x")]:
            b = copy.deepcopy(body)
            mutate(b)
            with self.subTest(summary=str(b["summary"])[:80]):
                self.assert_unevaluated(self.t.transform(b))

    def test_truncated_summary_never_fails_or_passes_on_weak_global(self):
        self.assert_unevaluated(self.t.transform(bodies(DOC_DEFAULT, truncated=True)))

    def test_global_policy_problems(self):
        no_global = bodies(ALL_WEAK_BLOCKED)
        no_global["policies"]["response"][0]["is_global_policy"] = False
        self.assert_unevaluated(self.t.transform(no_global))
        two = bodies(ALL_WEAK_BLOCKED, [("POC1", "Other", ALL_WEAK_BLOCKED, None)], applied=["POC1"])
        two["policies"]["response"][1]["is_global_policy"] = True
        self.assert_unevaluated(self.t.transform(two))
        self.assert_unevaluated(self.t.transform(bodies(None)))

    def test_wrong_typed_method_lists(self):
        for meth in [{"allowed_auth_list": 5, "blocked_auth_list": []},
                     {"allowed_auth_list": [], "blocked_auth_list": {"sms": True}},
                     {"allowed_auth_list": [], "blocked_auth_list": ["sms", 3]}]:
            with self.subTest(meth=str(meth)):
                self.assert_unevaluated(self.t.transform(bodies(meth)))

    def test_unknown_method_without_weak_is_unevaluated(self):
        meth = methods(["sms", "phonecall", "bypass", "bypass-pwl"], ["duo-push", "brand-new-method"])
        self.assert_unevaluated(self.t.transform(bodies(meth)))

    def test_everything_blocked_is_unevaluated(self):
        everything = ["sms", "phonecall", "bypass", "bypass-pwl", "duo-push", "duo-push-pwl", "webauthn-platform",
                      "webauthn-roaming", "webauthn-require-user-verification", "webauthn-platform-pwl",
                      "webauthn-roaming-pwl", "smart-card", "duo-passcode", "hardware-token", "desktop"]
        self.assert_unevaluated(self.t.transform(bodies(methods(everything))))

    def test_policy_entry_not_an_object(self):
        body = bodies(ALL_WEAK_BLOCKED)
        body["policies"]["response"].append("junk")
        body["summary"]["response"]["policy_count"] = 2
        self.assert_unevaluated(self.t.transform(body))

    def test_exception_is_unevaluated(self):
        real = self.t.evaluate

        def boom(body):
            raise RuntimeError("boom")

        try:
            self.t.evaluate = boom
            self.assert_unevaluated(self.t.transform(bodies(ALL_WEAK_BLOCKED)))
        finally:
            self.t.evaluate = real

    def test_never_true_on_no_evidence(self):
        for payload in [{}, None, "", {"policies": {}, "summary": {}}, {"policies": [], "summary": {"policies": []}}]:
            with self.subTest(payload=str(payload)[:60]):
                self.assertIsNot(self.value(payload), True)


if __name__ == "__main__":
    unittest.main()
