"""Duo isConditionalAccessEnabled from Policies v2 (GET /admin/v2/policies + /admin/v2/policies/summary).

Synthetic bodies for "estate A" in the documented shapes (Duo Admin API "Retrieve Policies", "Summarize
Policies" and "Policy Section Data"). Policy keys, app names and integration keys are invented. No customer data.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

KEY = "isConditionalAccessEnabled"
GLOBAL_KEY = "POGLOBALESTATEA00001"
VPN_KEY = "POVPNESTATEA00000001"
SPARE_KEY = "POSPAREESTATEA000001"

# Sections a Premier global policy returns with Duo's documented defaults: none is an access condition.
DEFAULTS = {
    "authentication_methods": {"allowed_auth_list": ["duo-push", "webauthn-roaming"],
                               "blocked_auth_list": ["desktop", "duo-passcode", "phonecall"]},
    "authentication_policy": {"user_auth_behavior": "enforce"},
    "new_user": {"new_user_behavior": "enroll"},
    "remembered_devices": {"browser_apps": {"enabled": True, "remember_method": "risk-based",
                                            "risk_based": {"max_time_units": "days", "max_time_value": 30}}},
    "risk_based_factor_selection": {"limit_to_risk_based_auth_methods": True},
    "screen_lock": {"require_screen_lock": True},
    "tampered_devices": {"block_tampered_devices": True},
    "duo_mobile_app": {"block_policy": "less-than-version", "block_version": "3.8.0"},
    "user_location": {"default_action": "ignore-location", "deny_access_countries_list": [],
                      "require_mfa_countries_list": [], "ignore_location_countries_list": []},
    "anonymous_networks": {"anonymous_access_behavior": "no-action"},
    "authorized_networks": {"no_2fa_required": {"ip_list": [], "require_enrollment": True},
                            "mfa_required": {"ip_list": []}, "deny_other_access": False, "blocked": {"ip_list": []}},
    "trusted_endpoints": {"trusted_endpoint_checking": "allow-all"},
    "browsers": {"blocked_browsers_list": [], "out_of_date_behavior": "no-remediation"},
    "operating_systems": {"allow_unrestricted_os_list": ["android", "ios", "macos", "windows"], "block_os_list": [],
                          "os_restrictions": {"ios": {"block_policy": "no-remediation", "warn_policy": "no-remediation"}}},
    "full_disk_encryption": {"require_encryption": False},
    "health_checks": {"requires_duo_desktop": [], "enforce_encryption": [], "enforce_firewall": [],
                      "enforce_system_password": [], "enforce_signed_payload": "no-enforcement"},
    "plugins": {"flash": "block-all", "java": "warn-only"},
    "mobile_device_biometrics": {"require_biometrics": False},
}

GEO_BLOCK = {"user_location": {"default_action": "ignore-location", "deny_access_countries_list": ["XA", "XB"]}}


def with_sections(base, **changes):
    out = copy.deepcopy(base)
    out.update(copy.deepcopy(changes))
    return out


def policy(key, name, sections, is_global=False):
    return {"policy_key": key, "policy_name": name, "is_global_policy": is_global, "sections": sections}


def bodies(global_sections, customs=(), applied=(), truncated=False, count=None):
    """customs: [(key, name, sections)]; applied: keys applied to an application."""
    pols = [policy(GLOBAL_KEY, "Global Policy", copy.deepcopy(global_sections), True)]
    for key, name, sections in customs:
        pols.append(policy(key, name, copy.deepcopy(sections)))
    summary = []
    for p in pols:
        applies = []
        if p["policy_key"] in applied:
            applies = [{"app_integration_key": "DIESTATEA00000000001", "app_name": "Estate A VPN", "apply_type": "app"}]
        summary.append({"policy_key": p["policy_key"], "policy_name": p["policy_name"], "policy_applies_to": applies})
    return {"policies": {"response": pols},
            "summary": {"response": {"policies": summary, "policy_count": len(pols) if count is None else count,
                                     "response_is_truncated": truncated, "warnings": []}}}


def load():
    spec = importlib.util.spec_from_file_location("duo_conditional_access",
                                                  Path(__file__).with_name("isConditionalAccessEnabled.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ts_is_equals(actual, expected=True):
    """Token-Service isEquals on the transformed value (a None never satisfies it)."""
    return actual is not None and str(actual).lower() == str(expected).lower()


class DuoConditionalAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def value(self, payload):
        out = self.t.transform(payload)
        return out["transformedResponse"][KEY], out

    def assertUnevaluated(self, payload, fragment=None):
        value, out = self.value(payload)
        self.assertIsNone(value)
        errors = out["additionalInfo"]["dataCollection"]["errors"] + out["additionalInfo"]["transformation"]["errors"]
        self.assertTrue(errors, "an Unevaluated result must carry its reason")
        if fragment:
            self.assertIn(fragment, json.dumps(out))
        return out

    # ---- True -------------------------------------------------------------------------------------
    def test_real_shape_global_geo_block_is_true(self):
        value, out = self.value(bodies(with_sections(DEFAULTS, **GEO_BLOCK)))
        self.assertIs(value, True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertIn("2 countries denied", json.dumps(out))

    def test_each_condition_alone_is_true(self):
        cases = {
            "deny unlisted countries": {"user_location": {"default_action": "deny-access"}},
            "anonymous deny": {"anonymous_networks": {"anonymous_access_behavior": "deny"}},
            "deny other networks": {"authorized_networks": {"deny_other_access": True,
                                                            "mfa_required": {"ip_list": ["192.0.2.0/24"]}}},
            "blocked networks": {"authorized_networks": {"blocked": {"ip_list": ["198.51.100.7"]}}},
            "trusted endpoints": {"trusted_endpoints": {"trusted_endpoint_checking": "require-trusted"}},
            "health requires app": {"health_checks": {"requires_duo_desktop": ["windows", "macos"]}},
            "legacy desktop encryption": {"duo_desktop": {"enforce_encryption": "windows,macos"}},
            "edr agent": {"health_checks": {"windows_endpoint_security_list": ["windows-defender"]}},
            "signed payload": {"health_checks": {"enforce_signed_payload": "enforce-enabled"}},
            "blocked os": {"operating_systems": {"block_os_list": ["windowsphone"]}},
            "out of date os": {"operating_systems": {"os_restrictions": {"windows": {"block_policy": "end-of-life"}}}},
            "blocked browser": {"browsers": {"blocked_browsers_list": "ie"}},
            "out of date browser": {"browsers": {"out_of_date_behavior": "warn-and-block"}},
            "disk encryption": {"full_disk_encryption": {"require_encryption": True}},
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], True)

    def test_custom_policy_inherits_global_condition(self):
        customs = [(VPN_KEY, "VPN remembered devices", {"remembered_devices": {"browser_apps": {"enabled": False}}})]
        self.assertIs(self.value(bodies(with_sections(DEFAULTS, **GEO_BLOCK), customs, applied=[VPN_KEY]))[0], True)

    def test_every_governing_policy_with_own_condition_is_true(self):
        customs = [(VPN_KEY, "VPN trusted only", {"trusted_endpoints": {"trusted_endpoint_checking": "require-trusted"}})]
        self.assertIs(self.value(bodies(with_sections(DEFAULTS, **GEO_BLOCK), customs, applied=[VPN_KEY]))[0], True)

    def test_string_booleans_and_comma_lists(self):
        b = bodies(with_sections(DEFAULTS, full_disk_encryption={"require_encryption": "True"}))
        b["policies"]["response"][0]["is_global_policy"] = "true"
        b["summary"]["response"]["response_is_truncated"] = "False"
        b["summary"]["response"]["policy_count"] = "1"
        self.assertIs(self.value(b)[0], True)

    def test_string_and_bytes_input(self):
        b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        self.assertIs(self.value(json.dumps(b))[0], True)
        self.assertIs(self.value(json.dumps(b).encode("utf-8"))[0], True)

    def test_wrapped_input(self):
        self.assertIs(self.value({"result": bodies(with_sections(DEFAULTS, **GEO_BLOCK))})[0], True)

    # ---- False (flipped) --------------------------------------------------------------------------
    def test_documented_defaults_only_is_false(self):
        value, out = self.value(bodies(DEFAULTS))
        self.assertIs(value, False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])

    def test_global_with_no_sections_is_false(self):
        self.assertIs(self.value(bodies({}))[0], False)

    def test_require_mfa_settings_are_not_conditions(self):
        change = {"user_location": {"default_action": "require-mfa", "require_mfa_countries_list": ["XA"]},
                  "anonymous_networks": {"anonymous_access_behavior": "require-mfa"}}
        self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], False)

    def test_bypass_lists_and_remembered_devices_are_not_conditions(self):
        change = {"authorized_networks": {"no_2fa_required": {"ip_list": ["192.0.2.0/24"]}},
                  "remembered_devices": {"browser_apps": {"enabled": True, "remember_method": "user-based"}}}
        self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], False)

    def test_unapplied_custom_condition_does_not_count(self):
        customs = [(SPARE_KEY, "Unapplied geo block", GEO_BLOCK)]
        self.assertIs(self.value(bodies(DEFAULTS, customs, applied=[]))[0], False)

    def test_applied_custom_without_condition_and_defaults_global_is_false(self):
        customs = [(VPN_KEY, "VPN", {"remembered_devices": {}})]
        self.assertIs(self.value(bodies(DEFAULTS, customs, applied=[VPN_KEY]))[0], False)

    def test_flip_geo_block_off(self):
        on = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        off = copy.deepcopy(on)
        off["policies"]["response"][0]["sections"]["user_location"]["deny_access_countries_list"] = []
        self.assertIs(self.value(on)[0], True)
        self.assertIs(self.value(off)[0], False)

    # ---- Partial / mixed: Unevaluated ---------------------------------------------------------------
    def test_custom_overriding_condition_away_is_unevaluated(self):
        customs = [(VPN_KEY, "VPN location ignored", {"user_location": {"default_action": "ignore-location"}})]
        self.assertUnevaluated(bodies(with_sections(DEFAULTS, **GEO_BLOCK), customs, applied=[VPN_KEY]), "differ")

    def test_condition_only_on_one_app_is_unevaluated(self):
        customs = [(VPN_KEY, "VPN geo block", GEO_BLOCK)]
        self.assertUnevaluated(bodies(DEFAULTS, customs, applied=[VPN_KEY]), "differ")

    def test_truncated_summary_is_unevaluated(self):
        self.assertUnevaluated(bodies(with_sections(DEFAULTS, **GEO_BLOCK), truncated=True), "truncated")

    def test_missing_truncation_flag_is_unevaluated(self):
        b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        del b["summary"]["response"]["response_is_truncated"]
        self.assertUnevaluated(b)

    def test_count_mismatch_is_unevaluated(self):
        self.assertUnevaluated(bodies(with_sections(DEFAULTS, **GEO_BLOCK), count=4), "summary counts 4")

    def test_no_global_policy_is_unevaluated(self):
        b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        b["policies"]["response"][0]["is_global_policy"] = False
        self.assertUnevaluated(b, "exactly one global policy")

    def test_two_global_policies_is_unevaluated(self):
        b = bodies(with_sections(DEFAULTS, **GEO_BLOCK), [(SPARE_KEY, "Second", {})])
        b["policies"]["response"][1]["is_global_policy"] = True
        self.assertUnevaluated(b, "exactly one global policy")

    def test_unreadable_settings_are_unevaluated(self):
        cases = {
            "sections not object": lambda b: b["policies"]["response"][0].__setitem__("sections", ["user_location"]),
            "section not object": lambda b: b["policies"]["response"][0]["sections"].__setitem__("browsers", "ie"),
            "flag not boolean": lambda b: b["policies"]["response"][0]["sections"].__setitem__(
                "full_disk_encryption", {"require_encryption": "sometimes"}),
            "deny_other not boolean": lambda b: b["policies"]["response"][0]["sections"].__setitem__(
                "authorized_networks", {"deny_other_access": "maybe"}),
            "list not list": lambda b: b["policies"]["response"][0]["sections"].__setitem__(
                "operating_systems", {"block_os_list": 7}),
            "restrictions not object": lambda b: b["policies"]["response"][0]["sections"].__setitem__(
                "operating_systems", {"os_restrictions": ["windows"]}),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                b = bodies(DEFAULTS)
                mutate(b)
                self.assertUnevaluated(b, "cannot be read")

    def test_stringified_empty_values_are_not_conditions(self):
        # Integration-Service can stringify an empty or false field; none of these is an access condition.
        cases = {
            "requires app False": {"health_checks": {"requires_duo_desktop": "False"}},
            "encryption []": {"duo_desktop": {"enforce_encryption": "[]"}},
            "firewall none": {"health_checks": {"enforce_firewall": "none"}},
            "password null": {"health_checks": {"enforce_system_password": "null"}},
            "edr list empty json": {"health_checks": {"windows_endpoint_security_list": "[]"}},
            "countries empty": {"user_location": {"deny_access_countries_list": ""}},
            "blocked ips []": {"authorized_networks": {"blocked": {"ip_list": "[]"}}},
            "os list False": {"operating_systems": {"block_os_list": "False"}},
            "browsers none": {"browsers": {"blocked_browsers_list": "none"}},
            "list of empties": {"health_checks": {"requires_duo_desktop": ["", "none", "False"]}},
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], False)

    def test_only_explicit_os_block_policies_count(self):
        for policy_word in ("warn-only", "no-remediation", "something-new", ""):
            with self.subTest(policy_word):
                change = {"operating_systems": {"os_restrictions": {"windows": {"block_policy": policy_word}}}}
                self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], False)
        for policy_word in ("end-of-life", "not-up-to-date", "less-than-version", "less-than-latest-version"):
            with self.subTest(policy_word):
                change = {"operating_systems": {"os_restrictions": {"windows": {"block_policy": policy_word}}}}
                self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], True)

    def test_unknown_list_values_are_unevaluated_not_conditions(self):
        cases = {
            "platform": {"health_checks": {"requires_duo_desktop": ["toaster"]}},
            "country": {"user_location": {"deny_access_countries_list": ["Narnia"]}},
            "network": {"authorized_networks": {"blocked": {"ip_list": ["everyone"]}}},
            "os": {"operating_systems": {"block_os_list": ["plan9"]}},
            "browser": {"browsers": {"blocked_browsers_list": ["lynx-ng"]}},
            "malformed json list": {"health_checks": {"requires_duo_desktop": "[windows"}},
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.assertUnevaluated(bodies(with_sections(DEFAULTS, **change)))

    def test_json_list_string_is_read(self):
        change = {"health_checks": {"requires_duo_desktop": '["windows", "macos"]'}}
        self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], True)

    # ---- Error / empty / None ---------------------------------------------------------------------
    def test_error_bodies_are_unevaluated(self):
        cases = [
            {"policies": {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}, "summary": {"response": {}}},
            {"policies": {"response": []}, "summary": {"statusCode": 403, "message": "Forbidden"}},
            {"policies": {"error": True, "message": "HTTP 401"}, "summary": {}},
            {"status": "error", "message": "integration error"},
            {"statusCode": 500},
        ]
        for body in cases:
            with self.subTest(body=str(body)[:60]):
                out = self.assertUnevaluated(body)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_permission_hint_on_policy_error(self):
        body = {"policies": {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}, "summary": {"response": {}}}
        self.assertUnevaluated(body, "Grant resource - Read")

    def test_empty_and_none_are_unevaluated(self):
        for payload in (None, "", "   ", {}, [], {"policies": None, "summary": None},
                        {"policies": {"response": []}}, {"summary": {"response": {"policies": []}}}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertUnevaluated(payload)

    def test_empty_policy_list_with_matching_summary_is_unevaluated(self):
        body = {"policies": {"response": []},
                "summary": {"response": {"policies": [], "policy_count": 0, "response_is_truncated": False}}}
        self.assertUnevaluated(body, "exactly one global policy")

    def test_unrelated_json_is_unevaluated(self):
        self.assertUnevaluated({"users": [{"user_id": "DUESTATEA"}]})

    def test_invalid_json_string_is_transformation_error(self):
        value, out = self.value("{not json")
        self.assertIsNone(value)
        self.assertTrue(out["additionalInfo"]["transformation"]["errors"])

    # ---- Output contract --------------------------------------------------------------------------
    def test_output_is_bool_or_none_and_operator_simulation(self):
        payloads = [bodies(with_sections(DEFAULTS, **GEO_BLOCK)), bodies(DEFAULTS), bodies(DEFAULTS, truncated=True)]
        got = [self.value(p)[0] for p in payloads]
        self.assertEqual([type(v) for v in got], [bool, bool, type(None)])
        self.assertEqual([ts_is_equals(v) for v in got], [True, False, False])

    def test_reasons_carry_no_ip_addresses_or_country_codes(self):
        change = {"authorized_networks": {"blocked": {"ip_list": ["198.51.100.7"]}},
                  "user_location": {"deny_access_countries_list": ["XA"]}}
        text = json.dumps(self.value(bodies(with_sections(DEFAULTS, **change)))[1])
        self.assertNotIn("198.51.100.7", text)
        self.assertNotIn('"XA"', text)


if __name__ == "__main__":
    unittest.main()
