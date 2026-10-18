"""Duo isConditionalAccessEnabled, graded per application (workflow getApplicationPolicyCoverage).

Inputs: GET /admin/v2/policies, GET /admin/v2/policies/summary and GET /admin/v3/integrations, merged under
"policies", "summary" and "integrations". Synthetic bodies for "environment A" in the documented shapes (Duo Admin
API "Retrieve Policies", "Summarize Policies", "Policy Section Data" and "Retrieve Integrations"). Policy keys,
application names and integration keys are invented. No customer data.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

KEY = "isConditionalAccessEnabled"
PCT = "conditionalAccessAppPercentage"
HERE = Path(__file__).parent
ROOT = HERE.parents[2]
GLOBAL_KEY = "POGLOBALTENANTA00001"
VPN_KEY = "POVPNTENANTA00000001"
SPARE_KEY = "POSPARETENANTA000001"
GROUP_KEY = "POGROUPTENANTA000001"
GROUP_KEY_2 = "POGROUPTENANTA000002"
GROUP_ID = "DGXXXXXXXXXXXXXXXXXX"
RDP_APP = "DITENANTARDP00000001"
PORTAL = "DITENANTAPORTAL00001"
VPN_APP = "DITENANTAVPN00000001"

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
    "duo_desktop": {"requires_duo_desktop": []},
    "plugins": {"flash": "block-all", "java": "warn-only"},
    "mobile_device_biometrics": {"require_biometrics": False},
}

# An Essentials-tier global: no user_location / anonymous_networks sections at all, the rest at defaults.
ESSENTIALS = {
    "authorized_networks": {"blocked": {"ip_list": []}, "deny_other_access": False},
    "trusted_endpoints": {"trusted_endpoint_checking": "allow-all"},
    "duo_desktop": {"requires_duo_desktop": []},
}

GEO_BLOCK = {"user_location": {"default_action": "ignore-location", "deny_access_countries_list": ["XA", "XB"]}}
DESKTOP_WINDOWS = {"duo_desktop": {"requires_duo_desktop": ["windows"]}}


def with_sections(base, **changes):
    out = copy.deepcopy(base)
    out.update(copy.deepcopy(changes))
    return out


def policy(key, name, sections, is_global=False):
    return {"policy_key": key, "policy_name": name, "is_global_policy": is_global, "sections": sections}


def bodies(global_sections, customs=(), applied=(), truncated=False, count=None, apps=None, groups=()):
    """customs: [(key, name, sections)]; applied: custom keys each attached to its own application;
    apps: [(integration_key, name, policy_key or None)] replaces the default application list;
    groups: [(policy_key, integration_key)] application-group bindings."""
    pols = [policy(GLOBAL_KEY, "Global Policy", copy.deepcopy(global_sections), True)]
    for key, name, sections in customs:
        pols.append(policy(key, name, copy.deepcopy(sections)))
    if apps is None:
        apps = [(PORTAL, "Tenant A Portal", None)]
        for i, key in enumerate(applied):
            apps.append(("DITENANTAAPP%08d" % i, "Tenant A App %d" % i, key))
    integrations = []
    for ikey, name, pkey in apps:
        app = {"integration_key": ikey, "name": name, "type": "sso-generic"}
        if pkey is not None:
            app["policy_key"] = pkey
        integrations.append(app)
    summary = []
    for p in pols:
        applies = [{"app_integration_key": ikey, "app_name": name, "apply_type": "app"}
                   for ikey, name, pkey in apps if pkey == p["policy_key"]]
        applies.extend({"app_integration_key": ikey, "app_name": "RDP Application", "apply_type": "group_app",
                        "group_position": 1,
                        "groups": [{"group_id": GROUP_ID, "group_name": "Example Group"}]}
                       for gkey, ikey in groups if gkey == p["policy_key"])
        summary.append({"policy_key": p["policy_key"], "policy_name": p["policy_name"], "policy_applies_to": applies})
    return {"policies": {"response": pols},
            "summary": {"response": {"policies": summary, "policy_count": len(pols) if count is None else count,
                                     "response_is_truncated": truncated, "warnings": []}},
            "integrations": {"stat": "OK", "response": integrations, "metadata": {"total_objects": len(integrations)}}}


def load():
    spec = importlib.util.spec_from_file_location("duo_conditional_access",
                                                  HERE / "isConditionalAccessEnabled.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_sandboxed():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_duo_ca", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    rel = "safeguards/iam/duo/isConditionalAccessEnabled.py"
    return sandbox.load((ROOT / rel).read_text(), rel)["transform"]


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
        self.assertFalse([k for k, v in out["transformedResponse"].items() if v is True])
        info = out["additionalInfo"]
        # a read failure is a dataCollection or transformation error; an indeterminate application is a warning
        errors = info["dataCollection"]["errors"] + info["transformation"]["errors"] + info["validation"]["warnings"]
        self.assertTrue(errors, "an Unevaluated result must carry its reason")
        self.assertEqual(info["evaluation"]["passReasons"], [])
        if fragment:
            self.assertIn(fragment, json.dumps(out))
        return out

    # ---- True -------------------------------------------------------------------------------------
    def test_all_applications_covered_is_true_100(self):
        value, out = self.value(bodies(with_sections(DEFAULTS, **GEO_BLOCK)))
        self.assertIs(value, True)
        self.assertEqual(out["transformedResponse"][PCT], 100.0)
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
            "duo desktop windows list": {"duo_desktop": {"requires_duo_desktop": ["windows"]}},
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

    def test_app_without_policy_key_inherits_covered_global(self):
        value, out = self.value(bodies(with_sections(DEFAULTS, **GEO_BLOCK)))
        self.assertIs(value, True)
        self.assertEqual(out["transformedResponse"]["conditionalAccessAppsOnGlobalPolicy"], 1)

    def test_unrelated_app_section_inherits_global_restrictive_section(self):
        customs = [(VPN_KEY, "VPN remembered devices", {"remembered_devices": {"browser_apps": {"enabled": False}}})]
        value, out = self.value(bodies(with_sections(DEFAULTS, **GEO_BLOCK), customs, applied=[VPN_KEY]))
        self.assertIs(value, True)
        self.assertEqual(out["transformedResponse"][PCT], 100.0)

    def test_every_app_with_own_condition_is_true(self):
        customs = [(VPN_KEY, "VPN trusted only", {"trusted_endpoints": {"trusted_endpoint_checking": "require-trusted"}})]
        apps = [(VPN_APP, "Tenant A VPN", VPN_KEY)]
        self.assertIs(self.value(bodies(DEFAULTS, customs, apps=apps))[0], True)

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

    def test_integrations_as_bare_list_is_read(self):
        b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        b["integrations"] = b["integrations"]["response"]
        self.assertIs(self.value(b)[0], True)

    # ---- False ------------------------------------------------------------------------------------
    def test_none_covered_is_false_0(self):
        value, out = self.value(bodies(DEFAULTS))
        self.assertIs(value, False)
        self.assertEqual(out["transformedResponse"][PCT], 0.0)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])
        self.assertIn("Tenant A Portal", json.dumps(out["additionalInfo"]["evaluation"]["failReasons"]))

    def test_global_with_no_sections_is_false(self):
        self.assertIs(self.value(bodies({}))[0], False)

    def test_twenty_five_apps_one_covered_is_4_0(self):
        customs = [(VPN_KEY, "Desktop required", DESKTOP_WINDOWS)]
        customs += [("POCUSTOMTENANTA%05d" % i, "Custom %d" % i, {"trusted_endpoints":
                                                                  {"trusted_endpoint_checking": "allow-all"}})
                    for i in range(19)]
        apps = [(VPN_APP, "Tenant A VPN", VPN_KEY)]
        apps += [("DITENANTAAPP%08d" % i, "Tenant A App %02d" % i, "POCUSTOMTENANTA%05d" % (i % 19))
                 for i in range(24)]
        value, out = self.value(bodies(ESSENTIALS, customs, apps=apps))
        result = out["transformedResponse"]
        self.assertIs(value, False)
        self.assertEqual(result[PCT], 4.0)
        self.assertEqual((result["conditionalAccessAppsCovered"], result["conditionalAccessAppsTotal"]), (1, 25))
        reasons = json.dumps(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertIn("24 of 25", reasons)
        self.assertIn("and 14 more", reasons)
        self.assertNotIn("Tenant A VPN", reasons)

    def test_partial_names_uncovered_and_percentage(self):
        customs = [(VPN_KEY, "VPN geo block", GEO_BLOCK)]
        value, out = self.value(bodies(DEFAULTS, customs, applied=[VPN_KEY]))
        self.assertIs(value, False)
        self.assertEqual(out["transformedResponse"][PCT], 50.0)
        reasons = json.dumps(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertIn("Tenant A Portal", reasons)
        self.assertNotIn("Tenant A App 0", reasons)

    def test_relaxing_app_value_overrides_global_in_same_section(self):
        customs = [(VPN_KEY, "VPN location ignored",
                    {"user_location": {"default_action": "ignore-location", "deny_access_countries_list": []}})]
        apps = [(VPN_APP, "Tenant A VPN", VPN_KEY)]
        value, out = self.value(bodies(with_sections(DEFAULTS, **GEO_BLOCK), customs, apps=apps))
        self.assertIs(value, False)
        self.assertEqual(out["transformedResponse"][PCT], 0.0)

    def test_percentage_one_decimal(self):
        customs = [(VPN_KEY, "VPN geo block", GEO_BLOCK)]
        apps = [(VPN_APP, "Tenant A VPN", VPN_KEY), (PORTAL, "Tenant A Portal", None),
                ("DITENANTAMAIL0000001", "Tenant A Mail", None)]
        self.assertEqual(self.value(bodies(DEFAULTS, customs, apps=apps))[1]["transformedResponse"][PCT], 33.3)

    def test_require_mfa_settings_are_not_conditions(self):
        change = {"user_location": {"default_action": "require-mfa", "require_mfa_countries_list": ["XA"]},
                  "anonymous_networks": {"anonymous_access_behavior": "require-mfa"}}
        self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], False)

    def test_bypass_lists_and_remembered_devices_are_not_conditions(self):
        change = {"authorized_networks": {"no_2fa_required": {"ip_list": ["192.0.2.0/24"]}},
                  "remembered_devices": {"browser_apps": {"enabled": True, "remember_method": "user-based"}}}
        self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], False)

    def test_unattached_custom_condition_does_not_count(self):
        customs = [(SPARE_KEY, "Unattached geo block", GEO_BLOCK)]
        self.assertIs(self.value(bodies(DEFAULTS, customs))[0], False)

    def test_flip_desktop_requirement_off(self):
        on = bodies(with_sections(DEFAULTS, **DESKTOP_WINDOWS))
        off = copy.deepcopy(on)
        off["policies"]["response"][0]["sections"]["duo_desktop"]["requires_duo_desktop"] = []
        self.assertIs(self.value(on)[0], True)
        self.assertIs(self.value(off)[0], False)

    def test_stringified_empty_values_are_not_conditions(self):
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
        for policy_word in ("warn-only", "no-remediation", ""):
            with self.subTest(policy_word):
                change = {"operating_systems": {"os_restrictions": {"windows": {"block_policy": policy_word}}}}
                self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], False)
        for policy_word in ("end-of-life", "not-up-to-date", "less-than-version", "less-than-latest-version"):
            with self.subTest(policy_word):
                change = {"operating_systems": {"os_restrictions": {"windows": {"block_policy": policy_word}}}}
                self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], True)

    def test_endpoint_security_list_needs_a_known_vendor(self):
        for value in ("disabled", ["disabled"], "not-required"):
            with self.subTest(value):
                change = {"health_checks": {"windows_endpoint_security_list": value}}
                self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], False)
        for value in (["any-old-word"], "enabled"):
            with self.subTest(value):
                change = {"health_checks": {"macos_endpoint_security_list": value}}
                self.assertUnevaluated(bodies(with_sections(DEFAULTS, **change)))
        for value in (["crowdstrike"], "sentinelone,sophos", ["Windows-Defender"]):
            with self.subTest(value):
                change = {"health_checks": {"windows_endpoint_security_list": value}}
                self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], True)

    def test_json_list_string_is_read(self):
        change = {"health_checks": {"requires_duo_desktop": '["windows", "macos"]'}}
        self.assertIs(self.value(bodies(with_sections(DEFAULTS, **change)))[0], True)

    # ---- group_app bindings -----------------------------------------------------------------------
    # Duo's policy summary lists, for an application-group binding, the groups the policy applies to
    # (policy_applies_to[].groups[].group_id, plus group_position). The group policy governs those users; every
    # other user of the application keeps the application's own policy. Both must carry an access condition.
    def rdp_body(self, global_sections=None, group_sections=None, group_key=GROUP_KEY, covered_apps=18):
        """18 applications on the global policy plus one RDP application bound to a group policy."""
        global_sections = with_sections(DEFAULTS, **GEO_BLOCK) if global_sections is None else global_sections
        group_sections = DESKTOP_WINDOWS if group_sections is None else group_sections
        apps = [("DITENANTAAPP%08d" % i, "Example App %02d" % i, None) for i in range(covered_apps)]
        apps.append((RDP_APP, "RDP Application", None))
        return bodies(global_sections, [(group_key, "RDP group policy", group_sections)], apps=apps,
                      groups=[(group_key, RDP_APP)])

    def test_rdp_app_bound_to_a_group_with_a_covered_policy_is_covered(self):
        value, out = self.value(self.rdp_body())
        result = out["transformedResponse"]
        self.assertIs(value, True)
        self.assertEqual(result[PCT], 100.0)
        self.assertEqual((result["conditionalAccessAppsCovered"], result["conditionalAccessAppsTotal"],
                          result["conditionalAccessAppsIndeterminate"]), (19, 19, 0))
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"]["groupBindings"], 1)
        self.assertNotIn("DGXXXXXXXXXXXXXXXXXX", json.dumps(out))
        self.assertNotIn("Example Group", json.dumps(out))

    def test_group_binding_with_several_groups_on_one_policy_is_covered(self):
        b = self.rdp_body()
        target = b["summary"]["response"]["policies"][1]["policy_applies_to"][0]
        target["groups"] = [{"group_id": "DGXXXXXXXXXXXXXXXX%02d" % i, "group_name": "Example Group %d" % i}
                            for i in range(3)]
        self.assertIs(self.value(b)[0], True)

    def test_group_policy_that_relaxes_the_condition_leaves_the_app_uncovered(self):
        relax = {"user_location": {"default_action": "ignore-location", "deny_access_countries_list": []}}
        value, out = self.value(self.rdp_body(group_sections=relax))
        result = out["transformedResponse"]
        self.assertIs(value, False)
        self.assertEqual(result[PCT], 94.7)
        self.assertEqual(result["conditionalAccessAppsIndeterminate"], 0)
        reasons = json.dumps(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertIn("1 of 19", reasons)
        self.assertIn("RDP Application", reasons)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_group_binding_does_not_cover_users_outside_the_group(self):
        # the application's own policy (global here) has no condition; only the group policy has one
        value, out = self.value(self.rdp_body(global_sections=DEFAULTS, group_sections=GEO_BLOCK, covered_apps=0))
        self.assertIs(value, False)
        self.assertEqual(out["transformedResponse"][PCT], 0.0)
        self.assertIn("RDP Application", json.dumps(out["additionalInfo"]["evaluation"]["failReasons"]))

    def test_group_binding_on_a_custom_application_policy_uses_that_chain(self):
        customs = [(VPN_KEY, "VPN trusted only", {"trusted_endpoints": {"trusted_endpoint_checking": "require-trusted"}}),
                   (GROUP_KEY, "Group policy with no setting", {"remembered_devices": {}})]
        apps = [(RDP_APP, "RDP Application", VPN_KEY)]
        b = bodies(DEFAULTS, customs, apps=apps, groups=[(GROUP_KEY, RDP_APP)])
        self.assertIs(self.value(b)[0], True)

    def test_flip_group_policy_condition_flips_the_verdict(self):
        self.assertIs(self.value(self.rdp_body(group_sections={}))[0], True)  # inherits the covered global
        relax = {"user_location": {"default_action": "ignore-location", "deny_access_countries_list": []}}
        self.assertIs(self.value(self.rdp_body(group_sections=relax))[0], False)
        self.assertIs(self.value(self.rdp_body(group_sections=DESKTOP_WINDOWS))[0], True)

    def test_genuinely_uncovered_app_stays_false_beside_a_resolved_binding(self):
        apps = [(RDP_APP, "RDP Application", None), ("DITENANTAMAIL0000001", "Tenant A Mail", VPN_KEY)]
        customs = [(GROUP_KEY, "RDP group policy", DESKTOP_WINDOWS),
                   (VPN_KEY, "Mail location ignored",
                    {"user_location": {"default_action": "ignore-location", "deny_access_countries_list": []}})]
        value, out = self.value(bodies(with_sections(DEFAULTS, **GEO_BLOCK), customs, apps=apps,
                                       groups=[(GROUP_KEY, RDP_APP)]))
        self.assertIs(value, False)
        self.assertEqual(out["transformedResponse"][PCT], 50.0)
        reasons = json.dumps(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertIn("Tenant A Mail", reasons)
        self.assertNotIn("RDP Application", reasons)

    def unresolved(self, mutate, fragment=None):
        b = self.rdp_body()
        mutate(b["summary"]["response"]["policies"][1]["policy_applies_to"][0])
        out = self.assertUnevaluated(b, fragment)
        self.assertEqual(out["transformedResponse"]["conditionalAccessAppsIndeterminate"], 1)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertEqual(out["transformedResponse"][PCT], round(18 * 100.0 / 19, 1))
        return out

    def test_group_binding_without_a_groups_list_is_unevaluated_never_false(self):
        cases = {
            "groups missing": lambda t: t.pop("groups"),
            "groups none": lambda t: t.__setitem__("groups", None),
            "groups empty": lambda t: t.__setitem__("groups", []),
            "groups a string": lambda t: t.__setitem__("groups", "DGXXXXXXXXXXXXXXXXXX"),
            "groups an object": lambda t: t.__setitem__("groups", {"group_id": GROUP_ID}),
            "old shape: group_name only": lambda t: (t.pop("groups"), t.__setitem__("group_name", "Example Group")),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                self.unresolved(mutate, "group")

    def test_partly_readable_groups_are_unevaluated_never_false(self):
        good = {"group_id": GROUP_ID, "group_name": "Example Group"}
        cases = {
            "entry not an object": [good, "DGXXXXXXXXXXXXXXXXXX"],
            "entry without group_id": [good, {"group_name": "Example Group"}],
            "group_id none": [good, {"group_id": None}],
            "group_id blank": [good, {"group_id": "  "}],
            "group_id a number": [{"group_id": 12345}],
        }
        for label, groups in cases.items():
            with self.subTest(label):
                self.unresolved(lambda t, g=groups: t.__setitem__("groups", g))

    def test_unresolved_binding_stays_unevaluated_even_when_the_app_policy_is_uncovered(self):
        b = self.rdp_body(global_sections=DEFAULTS, group_sections=GEO_BLOCK, covered_apps=0)
        del b["summary"]["response"]["policies"][1]["policy_applies_to"][0]["groups"]
        value, out = self.value(b)
        self.assertIsNone(value)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_unresolved_binding_with_an_uncovered_app_is_false_for_the_uncovered_app(self):
        apps = [(RDP_APP, "RDP Application", None), ("DITENANTAMAIL0000001", "Tenant A Mail", None)]
        customs = [(GROUP_KEY, "RDP group policy", GEO_BLOCK)]
        b = bodies(DEFAULTS, customs, apps=apps, groups=[(GROUP_KEY, RDP_APP)])
        del b["summary"]["response"]["policies"][1]["policy_applies_to"][0]["groups"]
        value, out = self.value(b)
        self.assertIs(value, False)
        self.assertEqual(out["transformedResponse"]["conditionalAccessAppsIndeterminate"], 1)
        reasons = json.dumps(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertIn("Tenant A Mail", reasons)
        self.assertNotIn("RDP Application", reasons)

    def test_two_different_group_policies_on_one_app_are_unevaluated(self):
        customs = [(GROUP_KEY, "RDP group policy one", DESKTOP_WINDOWS), (GROUP_KEY_2, "RDP group policy two", GEO_BLOCK)]
        b = bodies(with_sections(DEFAULTS, **GEO_BLOCK), customs, apps=[(RDP_APP, "RDP Application", None)],
                   groups=[(GROUP_KEY, RDP_APP), (GROUP_KEY_2, RDP_APP)])
        out = self.assertUnevaluated(b, "more than one")
        self.assertEqual(out["transformedResponse"]["conditionalAccessAppsIndeterminate"], 1)

    def test_unreadable_group_policy_is_unevaluated(self):
        customs = [(GROUP_KEY, "Group broken", {"browsers": "ie"})]
        self.assertUnevaluated(bodies(with_sections(DEFAULTS, **GEO_BLOCK), customs, groups=[(GROUP_KEY, PORTAL)]),
                               "cannot be read")

    def test_group_binding_to_unlisted_app_is_unevaluated(self):
        customs = [(GROUP_KEY, "Group geo block", GEO_BLOCK)]
        self.assertUnevaluated(bodies(DEFAULTS, customs, groups=[(GROUP_KEY, "DIUNLISTED0000000001")]), "incomplete")

    def test_group_binding_naming_an_unlisted_policy_is_unevaluated(self):
        b = self.rdp_body()
        b["summary"]["response"]["policies"][1]["policy_key"] = "PONOTINTHELIST000001"
        self.assertUnevaluated(b)

    def test_summary_that_hides_its_bindings_is_unevaluated(self):
        cases = {
            "policy_applies_to missing": lambda p: p[1].pop("policy_applies_to"),
            "policy_applies_to none": lambda p: p[1].__setitem__("policy_applies_to", None),
            "policy_applies_to a string": lambda p: p[1].__setitem__("policy_applies_to", "all"),
            "policy_applies_to an object": lambda p: p[1].__setitem__("policy_applies_to", {"apply_type": "app"}),
            "policy_applies_to entry not an object": lambda p: p[1]["policy_applies_to"].append("DITENANTA"),
            "apply_type missing": lambda p: p[1]["policy_applies_to"][0].pop("apply_type"),
            "apply_type unknown": lambda p: p[1]["policy_applies_to"][0].__setitem__("apply_type", "everyone"),
            "summary entry not an object": lambda p: p.append("POEXAMPLE"),
            "summary lacks a policy": lambda p: p.pop(1),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                b = self.rdp_body()
                mutate(b["summary"]["response"]["policies"])
                out = self.assertUnevaluated(b)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_error_or_empty_summary_with_group_bound_app_is_unevaluated(self):
        marker = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden",
                                            "body": {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}}}
        for summary in (marker, {"statusCode": 403, "message": "Forbidden"}, {"stat": "FAIL", "code": 40301},
                        {}, {"response": {}}, {"response": {"policies": []}}, None, ""):
            with self.subTest(summary=str(summary)[:50]):
                b = self.rdp_body()
                b["summary"] = summary
                out = self.assertUnevaluated(b)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_group_binding_verdicts_hold_in_the_production_sandbox(self):
        sandboxed = load_sandboxed()
        relax = {"user_location": {"default_action": "ignore-location", "deny_access_countries_list": []}}
        broken = self.rdp_body()
        del broken["summary"]["response"]["policies"][1]["policy_applies_to"][0]["groups"]
        cases = [(self.rdp_body(), True), (self.rdp_body(group_sections=relax), False), (broken, None)]
        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertIs(sandboxed(copy.deepcopy(payload))["transformedResponse"][KEY], expected)

    # ---- Unevaluated ------------------------------------------------------------------------------
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

    def test_unknown_policy_key_is_unevaluated(self):
        apps = [(VPN_APP, "Tenant A VPN", "PONOTINTHELIST000001")]
        self.assertUnevaluated(bodies(with_sections(DEFAULTS, **GEO_BLOCK), apps=apps), "policy_key")

    def test_missing_empty_or_non_list_integrations_is_unevaluated(self):
        cases = {
            "missing": lambda b: b.pop("integrations"),
            "empty list": lambda b: b.__setitem__("integrations", {"stat": "OK", "response": []}),
            "bare empty": lambda b: b.__setitem__("integrations", []),
            "not a list": lambda b: b.__setitem__("integrations", {"stat": "OK", "response": "apps"}),
            "none": lambda b: b.__setitem__("integrations", None),
            "entry not object": lambda b: b["integrations"]["response"].append("DITENANTA"),
            "entry without key": lambda b: b["integrations"]["response"].append({"name": "Keyless"}),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
                mutate(b)
                self.assertUnevaluated(b)

    def test_incomplete_applications_read_is_unevaluated_never_true(self):
        def truncated_one_of_25(b):
            b["integrations"]["paginationTruncated"] = True
            b["integrations"]["metadata"]["total_objects"] = 25

        cases = {
            "paginationTruncated with 1 of 25": truncated_one_of_25,
            "paginationTruncated alone": lambda b: b["integrations"].__setitem__("paginationTruncated", True),
            "paginationTruncated string": lambda b: b["integrations"].__setitem__("paginationTruncated", "true"),
            "response_metadata marker": lambda b: b["integrations"].__setitem__(
                "response_metadata", {"paginationTruncated": True}),
            "marker on merged body": lambda b: b.__setitem__("response_metadata", {"paginationTruncated": True}),
            "metadata.truncated": lambda b: b["integrations"]["metadata"].update({"truncated": True,
                                                                                  "scannedCount": 1}),
            "next_offset remains": lambda b: b["integrations"]["metadata"].__setitem__("next_offset", 500),
            "total_objects differs": lambda b: b["integrations"]["metadata"].__setitem__("total_objects", 25),
            "total_objects unreadable": lambda b: b["integrations"]["metadata"].__setitem__("total_objects", "many"),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
                self.assertIs(self.value(copy.deepcopy(b))[0], True)
                mutate(b)
                self.assertUnevaluated(b, "/admin/v3/integrations")

    def test_complete_read_markers_are_accepted(self):
        b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        b["integrations"]["paginationTruncated"] = False
        b["integrations"]["metadata"].update({"next_offset": None, "truncated": False, "total_objects": 1})
        self.assertIs(self.value(b)[0], True)

    def test_missing_policies_or_summary_is_unevaluated(self):
        for part in ("policies", "summary"):
            with self.subTest(part):
                b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
                del b[part]
                self.assertUnevaluated(b)

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
            "requires_duo_desktop as boolean": lambda b: b["policies"]["response"][0]["sections"].__setitem__(
                "duo_desktop", {"requires_duo_desktop": True}),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                b = bodies(DEFAULTS)
                mutate(b)
                self.assertUnevaluated(b, "cannot be read")

    def test_unknown_or_wrong_typed_enums_are_unevaluated(self):
        cases = {
            "default_action": {"user_location": {"default_action": "deny-sometimes"}},
            "anonymous": {"anonymous_networks": {"anonymous_access_behavior": "quarantine"}},
            "trusted": {"trusted_endpoints": {"trusted_endpoint_checking": "require-somewhat"}},
            "trusted wrong type": {"trusted_endpoints": {"trusted_endpoint_checking": True}},
            "browsers": {"browsers": {"out_of_date_behavior": "block-later"}},
            "signed payload": {"health_checks": {"enforce_signed_payload": ["enforce-enabled"]}},
            "os block policy": {"operating_systems": {"os_restrictions": {"windows": {"block_policy": "something-new"}}}},
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.assertUnevaluated(bodies(with_sections(DEFAULTS, **change)), "cannot be read")

    def test_unknown_list_values_are_unevaluated_not_conditions(self):
        cases = {
            "platform": {"health_checks": {"requires_duo_desktop": ["toaster"]}},
            "desktop platform": {"duo_desktop": {"requires_duo_desktop": ["toaster"]}},
            "country": {"user_location": {"deny_access_countries_list": ["Narnia"]}},
            "network": {"authorized_networks": {"blocked": {"ip_list": ["everyone"]}}},
            "os": {"operating_systems": {"block_os_list": ["plan9"]}},
            "browser": {"browsers": {"blocked_browsers_list": ["lynx-ng"]}},
            "malformed json list": {"health_checks": {"requires_duo_desktop": "[windows"}},
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.assertUnevaluated(bodies(with_sections(DEFAULTS, **change)))

    def test_error_bodies_are_unevaluated(self):
        good = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        cases = [
            dict(good, policies={"stat": "FAIL", "code": 40301, "message": "Access forbidden"}),
            dict(good, summary={"statusCode": 403, "message": "Forbidden"}),
            dict(good, integrations={"stat": "FAIL", "code": 40301, "message": "Access forbidden"}),
            dict(good, integrations={"error": True, "message": "HTTP 401"}),
            {"status": "error", "message": "integration error"},
            {"statusCode": 500},
        ]
        for body in cases:
            with self.subTest(body=str(body)[:60]):
                out = self.assertUnevaluated(body)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_vendor_error_marker_is_unevaluated(self):
        marker = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden",
                                            "body": {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}}}
        good = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        for body in (marker, dict(good, integrations=marker), dict(good, policies=marker)):
            with self.subTest(body=str(body)[:60]):
                self.assertUnevaluated(body, "Grant resource - Read")

    def test_permission_hint_on_policy_error(self):
        body = dict(bodies(DEFAULTS), policies={"stat": "FAIL", "code": 40301, "message": "Access forbidden"})
        self.assertUnevaluated(body, "Grant resource - Read")

    def test_empty_and_none_are_unevaluated(self):
        for payload in (None, "", "   ", {}, [], {"policies": None, "summary": None, "integrations": None},
                        {"policies": {"response": []}}, {"summary": {"response": {"policies": []}}},
                        {"integrations": {"response": []}}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertUnevaluated(payload)

    def test_empty_policy_list_with_matching_summary_is_unevaluated(self):
        body = dict(bodies(DEFAULTS), policies={"response": []},
                    summary={"response": {"policies": [], "policy_count": 0, "response_is_truncated": False}})
        self.assertUnevaluated(body, "exactly one global policy")

    def test_unrelated_json_is_unevaluated(self):
        self.assertUnevaluated({"users": [{"user_id": "DUTENANTA"}]})

    def test_invalid_json_string_is_transformation_error(self):
        value, out = self.value("{not json")
        self.assertIsNone(value)
        self.assertTrue(out["additionalInfo"]["transformation"]["errors"])

    def test_exception_is_unevaluated(self):
        b = bodies(with_sections(DEFAULTS, **GEO_BLOCK))
        original = self.t.conditions_of
        try:
            self.t.conditions_of = lambda chain: 1 / 0
            value, out = self.value(b)
        finally:
            self.t.conditions_of = original
        self.assertIsNone(value)
        self.assertTrue(out["additionalInfo"]["transformation"]["errors"])

    # ---- Output contract --------------------------------------------------------------------------
    def test_output_is_bool_or_none_and_operator_simulation(self):
        payloads = [bodies(with_sections(DEFAULTS, **GEO_BLOCK)), bodies(DEFAULTS), bodies(DEFAULTS, truncated=True)]
        got = [self.value(p)[0] for p in payloads]
        self.assertEqual([type(v) for v in got], [bool, bool, type(None)])
        self.assertEqual([ts_is_equals(v) for v in got], [True, False, False])

    def test_percentage_emitted_when_false_and_null_when_unevaluated(self):
        self.assertEqual(self.value(bodies(DEFAULTS))[1]["transformedResponse"][PCT], 0.0)
        self.assertIsNone(self.value(bodies(DEFAULTS, truncated=True))[1]["transformedResponse"][PCT])

    def test_reasons_carry_no_ip_addresses_or_country_codes(self):
        change = {"authorized_networks": {"blocked": {"ip_list": ["198.51.100.7"]}},
                  "user_location": {"deny_access_countries_list": ["XA"]}}
        text = json.dumps(self.value(bodies(with_sections(DEFAULTS, **change)))[1])
        self.assertNotIn("198.51.100.7", text)
        self.assertNotIn('"XA"', text)

    def test_never_true_from_empty_input(self):
        for payload in (None, {}, "{}", {"policies": {}, "summary": {}, "integrations": {}}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertIsNot(self.value(payload)[0], True)

    def test_production_sandbox_gives_the_same_verdicts(self):
        sandboxed = load_sandboxed()
        cases = [(bodies(with_sections(DEFAULTS, **GEO_BLOCK)), True), (bodies(DEFAULTS), False),
                 (bodies(DEFAULTS, truncated=True), None)]
        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertIs(sandboxed(copy.deepcopy(payload))["transformedResponse"][KEY], expected)


if __name__ == "__main__":
    unittest.main()
