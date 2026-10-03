"""Duo isConditionalAccessEnabled from Policies v2 (GET /admin/v2/policies + /admin/v2/policies/summary).

Synthetic bodies in the documented shapes (Duo Admin API "Retrieve Policies", "Summarize Policies" and
"Policy Section Data"). Policy keys, app names and integration keys are invented. No customer data.
"""
import importlib.util
import json
import unittest
from pathlib import Path

KEY = "isConditionalAccessEnabled"
GLOBAL_KEY = "POGLOBAL000000000001"
CUSTOM_KEY = "POCUSTOM00000000001"
SPARE_KEY = "POSPARE00000000000001"

DENY_LOCATION = {"user_location": {"default_action": "deny-access", "deny_access_countries_list": ["KP"],
                                   "access_device_only": False}}
RELAXING = {
    "user_location": {"default_action": "allow-access-no-2fa", "allow_access_no_2fa_countries_list": ["US"],
                      "ignore_location_countries_list": ["CA"]},
    "authorized_networks": {"no_2fa_required": {"ip_list": ["10.0.0.0/8"], "require_enrollment": False},
                            "deny_other_access": False},
    "anonymous_networks": {"anonymous_access_behavior": "no-action"},
    "trusted_endpoints": {"trusted_endpoint_checking": "allow-all"},
}
NOT_CONDITIONS = {"remembered_devices": {"remember_me": True, "remembered_for": 30},
                  "risk_based_factor_selection": {"enabled": True},
                  "operating_systems": {"windows": {"action": "block"}},
                  "browsers": {"chrome": {"action": "block"}},
                  "authentication_policy": {"user_auth_behavior": "enforce"},
                  "authentication_methods": {"allowed_auth_list": ["webauthn-roaming"], "blocked_auth_list": []}}


def policy(key, name, sections, is_global=False):
    return {"policy_key": key, "policy_name": name, "is_global_policy": is_global, "sections": sections}


def bodies(global_sections, customs=(), applied=(), apply_type="app", truncated=False, count=None):
    """customs: [(key, name, sections)]; applied: keys attached to an application."""
    pols = [policy(GLOBAL_KEY, "Global Policy", global_sections, True)]
    for key, name, sections in customs:
        pols.append(policy(key, name, sections))
    summary = []
    for p in pols:
        applies = []
        if p["policy_key"] in applied:
            applies = [{"app_integration_key": "DIEXAMPLE00000000001", "app_name": "Example VPN",
                        "apply_type": apply_type}]
        summary.append({"policy_key": p["policy_key"], "policy_name": p["policy_name"],
                        "policy_applies_to": applies})
    return {"policies": {"response": pols},
            "summary": {"response": {"policies": summary, "policy_count": len(pols) if count is None else count,
                                     "response_is_truncated": truncated, "warnings": []}}}


def load():
    spec = importlib.util.spec_from_file_location("duo_conditional_access",
                                                  Path(__file__).with_name("isConditionalAccessEnabled.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoConditionalAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def value(self, payload):
        out = self.t.transform(payload)
        return out["transformedResponse"][KEY], out

    def assertUnevaluated(self, payload):
        value, out = self.value(payload)
        self.assertIsNone(value)
        self.assertEqual(out["transformedResponse"], {KEY: None})
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        return out

    # ---- True -------------------------------------------------------------------------------------
    def test_global_location_deny_is_true(self):
        value, out = self.value(bodies(DENY_LOCATION))
        self.assertIs(value, True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_location_require_mfa_and_country_lists_are_true(self):
        for loc in ({"default_action": "require-mfa"},
                    {"default_action": "ignore-location", "require_mfa_countries_list": ["RU", "CN"]},
                    {"default_action": "ignore-location", "deny_access_countries_list": "KP, IR"}):
            with self.subTest(loc=loc):
                self.assertIs(self.value(bodies({"user_location": loc}))[0], True)

    def test_authorized_networks_mfa_required_array_and_string_are_true(self):
        for ips in (["203.0.113.0/24"], "203.0.113.0/24, 198.51.100.7"):
            with self.subTest(ips=ips):
                s = {"authorized_networks": {"mfa_required": {"ip_list": ips}}}
                self.assertIs(self.value(bodies(s))[0], True)

    def test_blocked_networks_and_deny_other_access_are_true(self):
        self.assertIs(self.value(bodies({"authorized_networks": {"blocked": {"ip_list": ["192.0.2.0/24"]}}}))[0], True)
        self.assertIs(self.value(bodies({"authorized_networks": {"deny_other_access": True}}))[0], True)
        self.assertIs(self.value(bodies({"authorized_networks": {"deny_other_access": "true"}}))[0], True)

    def test_anonymous_networks_require_mfa_or_deny_is_true(self):
        for behavior in ("require-mfa", "deny"):
            with self.subTest(behavior=behavior):
                s = {"anonymous_networks": {"anonymous_access_behavior": behavior}}
                self.assertIs(self.value(bodies(s))[0], True)

    def test_trusted_endpoints_require_trusted_is_true(self):
        s = {"trusted_endpoints": {"trusted_endpoint_checking": "require-trusted"}}
        self.assertIs(self.value(bodies(s))[0], True)

    def test_requires_duo_desktop_as_the_list_duo_really_returns(self):
        # Captured shape from a production tenant: a list of operating systems, [] when not required.
        self.assertIs(self.value(bodies({"duo_desktop": {"requires_duo_desktop": ["windows"],
                                                         "enforce_device_id_pinning": "never"}}))[0], True)
        self.assertIs(self.value(bodies({"health_checks": {"requires_duo_desktop": ["windows", "macos"]}}))[0], True)

    def test_empty_requires_duo_desktop_list_is_not_a_condition_and_not_a_problem(self):
        # The real global policy of an Essentials tenant: nothing contextual set, a complete read -> False.
        self.assertIs(self.value(bodies({"duo_desktop": {"requires_duo_desktop": [],
                                                         "enforce_device_id_pinning": "never",
                                                         "enforce_signed_payload": "never"}}))[0], False)

    def test_requires_duo_desktop_list_with_a_non_name_is_unevaluated(self):
        self.assertIsNone(self.value(bodies({"duo_desktop": {"requires_duo_desktop": [1, {}]}}))[0])

    def test_requires_duo_desktop_is_true(self):
        self.assertIs(self.value(bodies({"duo_desktop": {"requires_duo_desktop": True}}))[0], True)
        self.assertIs(self.value(bodies({"health_checks": {"requires_duo_desktop": True,
                                                           "enforce_firewall": True}}))[0], True)

    def test_attached_custom_policy_is_true_for_app_and_group_app(self):
        for apply_type in ("app", "group_app"):
            with self.subTest(apply_type=apply_type):
                customs = [(CUSTOM_KEY, "VPN geo", DENY_LOCATION)]
                b = bodies({}, customs, applied=[CUSTOM_KEY], apply_type=apply_type)
                self.assertIs(self.value(b)[0], True)

    def test_wrapped_and_json_string_inputs(self):
        for payload in ({"apiResponse": bodies(DENY_LOCATION)}, json.dumps(bodies(DENY_LOCATION)),
                        {"result": {"apiResponse": bodies(DENY_LOCATION)}}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertIs(self.value(payload)[0], True)

    def test_string_flags_in_global_and_truncation(self):
        b = bodies(DENY_LOCATION)
        b["policies"]["response"][0]["is_global_policy"] = "True"
        b["summary"]["response"]["response_is_truncated"] = "False"
        self.assertIs(self.value(b)[0], True)

    # ---- False ------------------------------------------------------------------------------------
    def test_unattached_custom_policy_does_not_count(self):
        customs = [(SPARE_KEY, "Unused geo", DENY_LOCATION)]
        value, out = self.value(bodies({}, customs, applied=[]))
        self.assertIs(value, False)
        self.assertIn("Essentials", out["additionalInfo"]["evaluation"]["failReasons"][0])
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])

    def test_relaxing_values_only_is_false(self):
        self.assertIs(self.value(bodies(RELAXING))[0], False)

    def test_each_relaxing_value_alone_is_false(self):
        for name, section in RELAXING.items():
            with self.subTest(section=name):
                self.assertIs(self.value(bodies({name: section}))[0], False)
        self.assertIs(self.value(bodies({"user_location": {"default_action": "ignore-location"}}))[0], False)
        self.assertIs(self.value(bodies({"trusted_endpoints": {"trusted_endpoint_checking": "not-configured"}}))[0], False)
        self.assertIs(self.value(bodies({"duo_desktop": {"requires_duo_desktop": False}}))[0], False)

    def test_remembered_devices_and_risk_based_are_not_conditions(self):
        self.assertIs(self.value(bodies(NOT_CONDITIONS))[0], False)

    def test_global_policy_with_empty_sections_is_false(self):
        self.assertIs(self.value(bodies({}))[0], False)
        b = bodies({})
        del b["policies"]["response"][0]["sections"]
        self.assertIs(self.value(b)[0], False)

    def test_attached_custom_with_only_relaxing_is_false(self):
        customs = [(CUSTOM_KEY, "Relaxed", RELAXING)]
        self.assertIs(self.value(bodies({}, customs, applied=[CUSTOM_KEY]))[0], False)

    # ---- Not evaluated ----------------------------------------------------------------------------
    def test_truncated_or_miscounted_summary_is_not_evaluated(self):
        self.assertUnevaluated(bodies(DENY_LOCATION, truncated=True))
        self.assertUnevaluated(bodies(DENY_LOCATION, count=7))
        b = bodies(DENY_LOCATION)
        del b["summary"]["response"]["response_is_truncated"]
        self.assertUnevaluated(b)

    def test_no_or_two_global_policies_are_not_evaluated(self):
        b = bodies(DENY_LOCATION)
        b["policies"]["response"][0]["is_global_policy"] = False
        self.assertUnevaluated(b)
        b = bodies(DENY_LOCATION, [(CUSTOM_KEY, "Other", {})], applied=[CUSTOM_KEY])
        b["policies"]["response"][1]["is_global_policy"] = True
        self.assertUnevaluated(b)

    def test_unknown_enum_values_are_not_evaluated(self):
        for sections in ({"user_location": {"default_action": "foo"}},
                         {"anonymous_networks": {"anonymous_access_behavior": "quarantine"}},
                         {"trusted_endpoints": {"trusted_endpoint_checking": "maybe"}}):
            with self.subTest(sections=sections):
                self.assertUnevaluated(bodies(sections))

    def test_wrong_typed_sections_are_not_evaluated(self):
        for sections in ({"user_location": "deny-access"}, {"authorized_networks": ["10.0.0.0/8"]},
                         {"authorized_networks": {"mfa_required": {"ip_list": 5}}},
                         {"authorized_networks": {"deny_other_access": "perhaps"}},
                         {"duo_desktop": {"requires_duo_desktop": "sometimes"}},
                         {"user_location": {"deny_access_countries_list": {"KP": True}}}):
            with self.subTest(sections=str(sections)[:50]):
                self.assertUnevaluated(bodies(sections))
        b = bodies({})
        b["policies"]["response"][0]["sections"] = ["user_location"]
        self.assertUnevaluated(b)

    def test_unreadable_section_in_an_unattached_policy_is_ignored(self):
        customs = [(SPARE_KEY, "Unused", {"user_location": {"default_action": "foo"}})]
        self.assertIs(self.value(bodies({}, customs, applied=[]))[0], False)

    def test_positive_evidence_survives_an_unreadable_sibling_section(self):
        s = dict(DENY_LOCATION)
        s["anonymous_networks"] = {"anonymous_access_behavior": "quarantine"}
        self.assertIs(self.value(bodies(s))[0], True)

    def test_no_evidence_inputs_are_not_evaluated(self):
        for payload in ({}, None, [], "", "   ", "{}", "not json at all", b"", 42,
                        {"policies": {"response": []}, "summary": {"response": {}}},
                        {"policies": {"response": []}}, {"summary": bodies(DENY_LOCATION)["summary"]},
                        {"policies": {"response": []}, "summary": {"response": {"policies": [], "policy_count": 0,
                                                                                "response_is_truncated": False}}}):
            with self.subTest(payload=str(payload)[:50]):
                self.assertUnevaluated(payload)

    def test_error_bodies_are_not_evaluated(self):
        errors = [
            {"stat": "FAIL", "code": 40103, "message": "Invalid signature in request credentials"},
            {"stat": "FAIL", "code": 40301, "message": "Access forbidden"},
            {"error": True, "errorType": "authentication", "statusCode": 401, "message": "Authentication Failed"},
            {"statusCode": 403, "message": "Forbidden"},
            {"statusCode": 500, "message": "Server error"},
        ]
        for err in errors:
            for part in ("policies", "summary"):
                b = bodies(DENY_LOCATION)
                b[part] = err
                with self.subTest(part=part, err=err.get("code") or err.get("statusCode")):
                    self.assertUnevaluated(b)
            with self.subTest(whole=str(err)[:30]):
                self.assertUnevaluated(err)

    def test_vendor_refusal_marker_is_unevaluated_and_names_no_permission(self):
        for status, body in ((403, {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}),
                             (500, {"stat": "FAIL", "code": 50000, "message": "boom"}),
                             (403, "{}"), (404, None)):
            marker = {"vendorErrorAsResponse": {"status": status, "bodyContains": "x", "body": body}}
            payloads = [marker, {"policies": marker, "summary": bodies(DENY_LOCATION)["summary"]},
                        {"policies": bodies(DENY_LOCATION)["policies"], "summary": marker},
                        {"apiResponse": {"policies": marker, "summary": marker}}, json.dumps(marker)]
            for payload in payloads:
                with self.subTest(status=status, payload=str(payload)[:40]):
                    out = self.assertUnevaluated(payload)
                    collection = out["additionalInfo"]["dataCollection"]
                    self.assertEqual(collection["errorCode"], "vendor_refusal")
                    self.assertIn("Duo refused the call", collection["errors"][0])
                    self.assertIn("HTTP %s" % status, collection["errors"][0])
                    self.assertNotIn("permission", json.dumps(collection).lower().replace("permitted", ""))
                    self.assertNotIn("Grant", json.dumps(out))

    def test_exception_path_is_unevaluated(self):
        class Boom(dict):
            def get(self, *a, **k):
                raise RuntimeError("boom")
        out = self.assertUnevaluated(Boom(policies={"response": []}, summary={"response": {}}))
        self.assertTrue(out["additionalInfo"]["transformation"]["errors"])

    # ---- Fail closed ------------------------------------------------------------------------------
    def test_never_true_from_empty_flipped_or_error_inputs(self):
        flipped = bodies({}, [(SPARE_KEY, "Unused geo", DENY_LOCATION)], applied=[])
        inputs = [{}, None, [], "", {"policies": [], "summary": {}}, {"stat": "FAIL"}, bodies(RELAXING), flipped,
                  bodies(NOT_CONDITIONS), {"policies": {"response": []},
                                           "summary": {"response": {"policies": [], "policy_count": 0,
                                                                    "response_is_truncated": False}}}]
        for payload in inputs:
            with self.subTest(payload=str(payload)[:50]):
                self.assertIsNot(self.value(payload)[0], True)

    def test_output_carries_only_the_criteria_key(self):
        for payload in (bodies(DENY_LOCATION), bodies({}), None):
            self.assertEqual(list(self.t.transform(payload)["transformedResponse"].keys()), [KEY])


if __name__ == "__main__":
    unittest.main()
