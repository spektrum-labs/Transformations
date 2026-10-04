"""hasHighRiskUserDetectionAPIAccess read from Duo Policies v2 (hasHighRiskUserDetectionByPolicy.py).

Shapes follow the Duo Admin API "Retrieve Policies" / "Summarize Policies" docs and the "Policy Section Data"
keys risk_based_factor_selection.limit_to_risk_based_auth_methods and
remembered_devices.browser_apps.{enabled, remember_method}. All keys, names and values are synthetic.
"""
import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TRANSFORMATION_PATH = HERE / "hasHighRiskUserDetectionByPolicy.py"
KEY = "hasHighRiskUserDetectionAPIAccess"

ESSENTIALS = {
    "authentication_methods": {"allowed_auth_list": ["duo-push"], "blocked_auth_list": ["sms"]},
    "authentication_policy": {"user_auth_behavior": "enforce"},
    "authorized_networks": {"deny_other_access": False},
    "duo_desktop": {"requires_duo_desktop": False},
    "new_user": {"new_user_behavior": "enroll"},
    "remembered_devices": {"browser_apps": {"enabled": False}, "windows_logon": {"enabled": False}},
    "trusted_endpoints": {"trusted_endpoint_checking": "not-configured"},
}


def advantage_global(rbfs=True, remember_method="risk-based", browser_enabled=True):
    sections = copy.deepcopy(ESSENTIALS)
    sections["screen_lock"] = {"require_screen_lock": True}
    sections["risk_based_factor_selection"] = {"limit_to_risk_based_auth_methods": rbfs,
                                               "risk_based_verified_push_digits": 6}
    browser = {"enabled": browser_enabled}
    if remember_method is not None:
        browser["remember_method"] = remember_method
    sections["remembered_devices"] = {"browser_apps": browser, "windows_logon": {"enabled": False}}
    return {"policy_key": "POGLOBAL000000000000", "policy_name": "Global Policy", "is_global_policy": True,
            "sections": sections}


def custom(key, sections):
    return {"policy_key": key, "policy_name": "Custom " + key[-4:], "is_global_policy": False, "sections": sections}


def body(policies, applied=None, truncated=False, count=None):
    applied = applied or []
    summary = []
    for p in policies:
        applies = [{"app_integration_key": "DI00000000000000000" + str(i), "app_name": "App", "apply_type": "app"}
                   for i in range(1)] if p["policy_key"] in applied else []
        summary.append({"policy_key": p["policy_key"], "policy_name": p["policy_name"], "policy_applies_to": applies})
    return {
        "policies": {"stat": "OK", "response": policies, "metadata": {"total_objects": len(policies)}},
        "summary": {"stat": "OK", "response": {"policies": summary,
                                               "policy_count": len(policies) if count is None else count,
                                               "response_is_truncated": truncated, "warnings": []}},
    }


RBFS_OFF = {"risk_based_factor_selection": {"limit_to_risk_based_auth_methods": False}}
RBRD_OFF = {"remembered_devices": {"browser_apps": {"enabled": True, "remember_method": "user-based"}}}


def load_transformation():
    spec = importlib.util.spec_from_file_location("duo_hasHighRiskUserDetectionByPolicy", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoHighRiskDetectionPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def verdict(self, payload):
        return self.t.transform(payload)["transformedResponse"][KEY]

    def assert_unevaluated(self, payload, needle=None):
        out = self.t.transform(payload)
        self.assertIsNone(out["transformedResponse"][KEY])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])
        if needle:
            self.assertIn(needle, out["additionalInfo"]["dataCollection"]["errors"][0])
        return out

    # ------------------------------------------------------------------ true

    def test_global_with_both_risk_settings_on_is_true(self):
        out = self.t.transform(body([advantage_global()]))
        self.assertIs(out["transformedResponse"][KEY], True)
        reasons = " ".join(out["additionalInfo"]["evaluation"]["passReasons"])
        self.assertIn("Risk-Based Factor Selection", reasons)
        self.assertIn("speaks only for the applications it protects", reasons)
        self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"]["edition"], "advantage-or-premier")

    def test_only_risk_based_factor_selection_on_is_true(self):
        self.assertIs(self.verdict(body([advantage_global(rbfs=True, remember_method="user-based")])), True)

    def test_only_risk_based_remembered_devices_on_is_true(self):
        self.assertIs(self.verdict(body([advantage_global(rbfs=False)])), True)

    def test_custom_policy_inherits_global_risk_settings(self):
        pol = [advantage_global(), custom("POCUSTOM000000000001", {"new_user": {"new_user_behavior": "enroll"}})]
        self.assertIs(self.verdict(body(pol, applied=["POCUSTOM000000000001"])), True)

    def test_global_on_with_an_applied_custom_policy_off_is_true_and_names_it(self):
        off = custom("POCUSTOM000000000001", dict(RBFS_OFF, **RBRD_OFF))
        out = self.t.transform(body([advantage_global(), off], applied=["POCUSTOM000000000001"]))
        self.assertIs(out["transformedResponse"][KEY], True)
        findings = out["additionalInfo"]["evaluation"]["additionalFindings"]
        self.assertEqual(len(findings), 1)
        self.assertIn("turns off", findings[0])

    def test_string_booleans(self):
        g = advantage_global(rbfs="True", remember_method="user-based", browser_enabled="True")
        self.assertIs(self.verdict(json.loads(json.dumps(body([g])))), True)

    def test_wrapped_and_json_string_inputs(self):
        b = body([advantage_global()])
        self.assertIs(self.verdict({"apiResponse": b}), True)
        self.assertIs(self.verdict(json.dumps(b)), True)
        self.assertIs(self.verdict(json.dumps(b).encode("utf-8")), True)

    # ------------------------------------------------------------------ false

    def test_documented_settings_both_off_is_false(self):
        out = self.t.transform(body([advantage_global(rbfs=False, remember_method="user-based")]))
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])
        self.assertIn("speaks only for the applications it protects",
                      out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_rbfs_off_and_browser_remembering_disabled_is_false(self):
        self.assertIs(self.verdict(body([advantage_global(rbfs=False, remember_method=None,
                                                          browser_enabled=False)])), False)

    def test_every_governing_policy_off_is_false(self):
        g = advantage_global(rbfs=False, remember_method="user-based")
        pol = [g, custom("POCUSTOM000000000001", dict(RBFS_OFF, **RBRD_OFF))]
        self.assertIs(self.verdict(body(pol, applied=["POCUSTOM000000000001"])), False)

    def test_unapplied_custom_policy_on_does_not_rescue_an_off_global(self):
        g = advantage_global(rbfs=False, remember_method="user-based")
        on = custom("POCUSTOM000000000001", {"risk_based_factor_selection": {"limit_to_risk_based_auth_methods": True}})
        self.assertIs(self.verdict(body([g, on])), False)

    # ------------------------------------------------------------------ not evaluated

    def test_essentials_edition_is_unevaluated_edition_lacks(self):
        g = {"policy_key": "POGLOBAL000000000000", "policy_name": "Global Policy", "is_global_policy": "True",
             "sections": json.loads(json.dumps(ESSENTIALS).replace("false", '"False"'))}
        out = self.assert_unevaluated(body([g]), "edition lacks risk-based authentication")
        self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"]["edition"], "essentials")

    def test_global_off_with_an_applied_custom_policy_on_is_unevaluated(self):
        g = advantage_global(rbfs=False, remember_method="user-based")
        on = custom("POCUSTOM000000000001", {"risk_based_factor_selection": {"limit_to_risk_based_auth_methods": True}})
        self.assert_unevaluated(body([g, on], applied=["POCUSTOM000000000001"]), "policies differ")

    def test_unclear_settings_are_unevaluated(self):
        g = advantage_global(rbfs=False, remember_method=None)  # browser remembering on, method not given
        self.assert_unevaluated(body([g]), "unclear")
        g = advantage_global(rbfs="maybe", remember_method="user-based")
        self.assert_unevaluated(body([g]))

    def test_global_on_with_an_unclear_custom_policy_is_unevaluated(self):
        bad = custom("POCUSTOM000000000001", {"risk_based_factor_selection": {"limit_to_risk_based_auth_methods": "x"},
                                              "remembered_devices": {"browser_apps": {"enabled": True}}})
        self.assert_unevaluated(body([advantage_global(rbfs=False, remember_method="risk-based"), bad],
                                     applied=["POCUSTOM000000000001"]))

    def test_error_bodies_are_unevaluated(self):
        fail = {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}
        good = body([advantage_global()])
        self.assert_unevaluated({"policies": fail, "summary": good["summary"]}, "Duo error 40301")
        self.assert_unevaluated({"policies": good["policies"], "summary": fail}, "Duo error 40301")
        self.assert_unevaluated({"error": True, "message": "boom"})
        self.assert_unevaluated({"statusCode": 401, "message": "Unauthorized"})

    def test_vendor_error_marker_is_unevaluated(self):
        marker = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden",
                                            "body": {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}}}
        self.assert_unevaluated(marker, "Grant resource - Read")
        good = body([advantage_global()])
        self.assert_unevaluated({"policies": marker, "summary": good["summary"]}, "Grant resource - Read")
        string_body = {"vendorErrorAsResponse": {"status": "403", "body": "not json"}}
        self.assert_unevaluated(string_body, "HTTP 403")
        self.assert_unevaluated({"vendorErrorAsResponse": {"status": 500, "body": {}}}, "error instead of policy data")

    def test_no_evidence_inputs_are_unevaluated(self):
        for payload in [None, {}, [], "", "{}", {"policies": {}, "summary": {}},
                        {"policies": {"response": []}, "summary": {"response": {"policies": [], "policy_count": 0,
                                                                                "response_is_truncated": False}}}]:
            self.assertIsNone(self.verdict(payload), payload)

    def test_truncated_or_miscounted_summary_is_unevaluated(self):
        self.assert_unevaluated(body([advantage_global()], truncated=True), "truncated")
        b = body([advantage_global()])
        del b["summary"]["response"]["response_is_truncated"]
        self.assert_unevaluated(b, "truncated")
        self.assert_unevaluated(body([advantage_global()], count=2), "summary counts 2")

    def test_no_or_two_global_policies_are_unevaluated(self):
        c = custom("POCUSTOM000000000001", {})
        self.assert_unevaluated(body([c]), "found 0")
        self.assert_unevaluated(body([advantage_global(), dict(advantage_global(), policy_key="POGLOBAL000000000001")]),
                                "found 2")

    def test_global_without_sections_is_unevaluated(self):
        g = advantage_global()
        g["sections"] = None
        self.assert_unevaluated(body([g]), "no sections")


class SandboxTests(unittest.TestCase):
    def test_compiles_and_runs_in_the_restricted_sandbox(self):
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import restricted_sandbox
        except ImportError:  # RestrictedPython not installed locally; CI's contract job compiles every file
            self.skipTest("RestrictedPython not installed")
        ns = restricted_sandbox.load(TRANSFORMATION_PATH.read_text())
        self.assertIs(ns["transform"](body([advantage_global()]))["transformedResponse"][KEY], True)
        self.assertIs(ns["transform"](body([advantage_global(rbfs=False, remember_method="user-based")]))
                      ["transformedResponse"][KEY], False)
        self.assertIsNone(ns["transform"](None)["transformedResponse"][KEY])
        out = ns["transform"]({"vendorErrorAsResponse": {"status": 403, "body": "{\"code\": 40301}"}})
        self.assertIsNone(out["transformedResponse"][KEY])
        self.assertEqual(out["additionalInfo"]["transformation"]["status"], "success")

    def test_no_forbidden_constructs(self):
        src = TRANSFORMATION_PATH.read_text()
        for bad in ["getattr(", "re.compile", "strptime", "import re"]:
            self.assertNotIn(bad, src)


if __name__ == "__main__":
    unittest.main()
