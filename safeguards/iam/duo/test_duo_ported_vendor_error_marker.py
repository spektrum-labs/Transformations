"""Duo isAdminMFAPhishingResistant / isStrongAuthRequiredByPolicy and Integration-Service's vendorErrorAsResponse marker.

Duo answers a missing Admin API permission with HTTP 403 {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}.
Only getAdmins (GET /admin/v1/admins) has a permission Duo's docs state ("Grant administrators - Read"); for
allowed_auth_methods, policies and policies/summary the docs name none, so none may be invented. A marker is Unevaluated
(None, dataCollection error), never False and never a pass, wherever it sits in the input.
"""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent
BODY_40301 = {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}
PERMISSION = "Grant administrators - Read"

WEBAUTHN_ONLY = {"hardware_token_enabled": False, "mobile_otp_enabled": False, "push_enabled": False,
                 "sms_enabled": False, "verified_push_enabled": False, "verified_push_length": None,
                 "voice_enabled": False, "webauthn_enabled": True, "yubikey_enabled": False}
ADMINS = {"response": [{"admin_id": "D1", "status": "Active", "webauthncredentials": [{"n": 1}]}]}
PR_ONLY = {"allowed_auth_list": ["webauthn-roaming"],
           "blocked_auth_list": ["duo-push", "duo-push-pwl", "sms", "phonecall", "duo-passcode", "hardware-token",
                                 "desktop", "bypass", "bypass-pwl"]}
POLICIES = {"response": [{"policy_key": "POG", "policy_name": "Global", "is_global_policy": True,
                          "sections": {"authentication_methods": PR_ONLY}}]}
SUMMARY = {"response": {"policies": [{"policy_key": "POG", "policy_name": "Global", "policy_applies_to": []}],
                        "policy_count": 1, "response_is_truncated": False}}


def load(name):
    spec = importlib.util.spec_from_file_location("duo_ported_marker_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def marker(status=403, body=BODY_40301):
    return {"vendorErrorAsResponse": {"status": status, "bodyContains": "Access forbidden", "body": body}}


# name, key, healthy payload, healthy value, {output key: (endpoint, permission or None)}
ADMIN_HEALTHY = {"allowedAuthMethods": {"response": WEBAUTHN_ONLY}, "admins": ADMINS}
POLICY_HEALTHY = {"policies": POLICIES, "summary": SUMMARY}
ADMIN_ENDPOINTS = {"admins": ("/admin/v1/admins", PERMISSION),
                   "allowedAuthMethods": ("/admin/v1/admins/allowed_auth_methods", None)}
POLICY_ENDPOINTS = {"policies": ("/admin/v2/policies", None), "summary": ("/admin/v2/policies/summary", None)}
CASES = [("isAdminMFAPhishingResistant", "isAdminMFAPhishingResistant", ADMIN_HEALTHY, ADMIN_ENDPOINTS),
         ("isStrongAuthRequiredByPolicy", "isStrongAuthRequired", POLICY_HEALTHY, POLICY_ENDPOINTS)]


class DuoPortedVendorErrorMarkerTests(unittest.TestCase):
    def check(self, out, key, endpoint=None, permission=None, code="permission_not_granted"):
        self.assertEqual(out["transformedResponse"], {key: None})
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertEqual(collection["errorCode"], code)
        text = " ".join(collection["errors"])
        if endpoint:
            self.assertIn(endpoint, text)
        if permission:
            self.assertEqual(collection["requiredPermission"], permission)
            self.assertIn(permission, text)
        else:
            self.assertNotIn("requiredPermission", collection)
            self.assertNotIn("Grant ", text)
        return text

    def test_healthy_payloads_unchanged(self):
        for name, key, healthy, _ in CASES:
            with self.subTest(name):
                out = load(name).transform(healthy)
                self.assertIs(out["transformedResponse"][key], True)
                self.assertNotIn("errorCode", out["additionalInfo"]["dataCollection"])

    def test_403_40301_under_each_output_key(self):
        for name, key, healthy, endpoints in CASES:
            t = load(name)
            for okey in endpoints:
                endpoint, permission = endpoints[okey]
                for body in (BODY_40301, json.dumps(BODY_40301)):
                    for shape in ("under", "nested", "string", "mixed"):
                        with self.subTest(name=name, key=okey, shape=shape, body=type(body).__name__):
                            if shape == "under":
                                payload = {okey: marker(403, body)}
                            elif shape == "nested":
                                payload = {"data": {okey: marker(403, body)}}
                            elif shape == "string":
                                payload = {okey: json.dumps(marker(403, body))}
                            else:
                                payload = dict(healthy)
                                payload[okey] = marker(403, body)
                            text = self.check(t.transform(payload), key, endpoint, permission)
                            if permission is None:
                                self.assertIn("does not name it", text)

    def test_top_level_marker_names_no_permission(self):
        for name, key, healthy, endpoints in CASES:
            for body in (BODY_40301, json.dumps(BODY_40301)):
                with self.subTest(name=name, body=type(body).__name__):
                    out = load(name).transform(marker(403, body))
                    text = self.check(out, key)
                    for okey in endpoints:
                        self.assertIn(endpoints[okey][0], text)

    def test_both_refused_names_both_endpoints(self):
        t = load("isAdminMFAPhishingResistant")
        out = t.transform({"admins": marker(), "allowedAuthMethods": marker()})
        text = self.check(out, "isAdminMFAPhishingResistant", "/admin/v1/admins", PERMISSION)
        self.assertIn("/admin/v1/admins/allowed_auth_methods", text)

    def test_other_refusals_are_vendor_refusal(self):
        others = [marker(401, {"stat": "FAIL", "code": 40101, "message": "Invalid signature"}),
                  marker(500, "boom"),
                  marker(403, {"stat": "FAIL", "code": 40301, "message": "Something else"}),
                  marker(403, {"stat": "FAIL", "code": 40302, "message": "Access forbidden"}),
                  marker(403, "not json")]
        for name, key, healthy, endpoints in CASES:
            for okey in endpoints:
                for m in others:
                    with self.subTest(name=name, key=okey, status=m["vendorErrorAsResponse"]["status"]):
                        out = load(name).transform({okey: m})
                        self.check(out, key, endpoints[okey][0], None, "vendor_refusal")
                        self.assertNotIn("PERMISSION", " ".join(out["additionalInfo"]["dataCollection"]["errors"]))

    def test_never_false_or_pass(self):
        for name, key, healthy, endpoints in CASES:
            for payload in (marker(), {"data": marker()}, {"apiResponse": {"response": marker()}}):
                with self.subTest(name=name, payload=str(payload)[:30]):
                    value = load(name).transform(payload)["transformedResponse"][key]
                    self.assertIsNone(value)

    def test_marker_inside_a_list_is_found(self):
        # A workflow output delivered as a list of step results must not fall through to the original parser.
        for name, key, healthy, endpoints in CASES:
            for okey in endpoints:
                with self.subTest(name=name, key=okey):
                    out = load(name).transform({okey: [marker()]})
                    self.check(out, key, endpoints[okey][0], endpoints[okey][1])
            with self.subTest(name=name, shape="top-level list"):
                out = load(name).transform([marker()])
                self.assertIsNone(out["transformedResponse"][key])
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
