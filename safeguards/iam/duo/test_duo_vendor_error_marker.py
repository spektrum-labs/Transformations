"""Duo settings/admin checks and Integration-Service's vendorErrorAsResponse marker.

Duo answers a missing Admin API permission with HTTP 403 {"stat": "FAIL", "code": 40301,
"message": "Access forbidden"}. getDuoSettings needs "Grant settings"; getAdmins needs
"Grant administrators - Read". When the method opts in, the refusal reaches the transformation as
{"vendorErrorAsResponse": {"status", "bodyContains", "body"}}. These four checks must report it
Unevaluated (every value None, dataCollection error), name the permission only for 403/40301, and
never return False or a pass.
"""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent

BODY_40301 = {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}

SETTINGS_OK = {"stat": "OK", "response": {
    "push_enabled": True, "sms_enabled": True, "voice_enabled": False, "mobile_otp_enabled": False,
    "minimum_password_length": 12, "password_requires_upper_alpha": True,
    "password_requires_lower_alpha": True, "password_requires_numeric": True,
    "password_requires_special": True}}

ADMINS_OK = {"stat": "OK", "response": [
    {"admin_id": "A1", "name": "Ann", "role": "Owner", "phone_details": [{"activated": True}]},
    {"admin_id": "A2", "name": "Bob", "role": "Help Desk", "webauthncredentials": [{"x": 1}]},
]}

# file, criteria key, required permission, healthy payload, healthy value
CASES = [
    ("authTypesAllowed", "authTypesAllowed", "Grant settings", SETTINGS_OK, True),
    ("confirmPasswordPolicyEnforced", "confirmPasswordPolicyEnforced", "Grant settings", SETTINGS_OK, True),
    ("superAdminMfaEnrollmentPercentage", "superAdminMfaEnrollmentPercentage",
     "Grant administrators - Read", ADMINS_OK, 100.0),
    ("isrbacimplemented", "isRBACImplemented", "Grant administrators - Read", ADMINS_OK, True),
]


def load(name):
    spec = importlib.util.spec_from_file_location("duo_marker_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def marker(status, body):
    return {"vendorErrorAsResponse": {"status": status, "bodyContains": "Access forbidden", "body": body}}


class DuoVendorErrorMarkerTests(unittest.TestCase):
    def each(self):
        return [(load(name), key, perm, ok, ok_value) for name, key, perm, ok, ok_value in CASES]

    def assert_unevaluated(self, response, key):
        result = response["transformedResponse"]
        self.assertIn(key, result)
        for k in result:
            self.assertIsNone(result[k], k)
        self.assertNotIn(False, [result[k] for k in result])
        collection = response["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertEqual(response["additionalInfo"]["evaluation"]["passReasons"], [])

    def assert_names_grant(self, response, perm):
        collection = response["additionalInfo"]["dataCollection"]
        text = " ".join(collection["errors"])
        self.assertIn('"' + perm + '"', text)
        self.assertIn("403", text)
        self.assertIn("40301", text)
        self.assertIn("Admin API application", text)
        self.assertEqual(collection["errorCode"], "permission_not_granted")
        self.assertEqual(collection["requiredPermission"], perm)
        self.assertIn(perm, response["additionalInfo"]["evaluation"]["recommendations"][0])

    def assert_generic(self, response, status):
        collection = response["additionalInfo"]["dataCollection"]
        text = " ".join(collection["errors"]) + " ".join(response["additionalInfo"]["evaluation"]["recommendations"])
        self.assertIn("HTTP " + str(status), text)
        self.assertNotIn("Grant ", text)
        self.assertEqual(collection["errorCode"], "vendor_refusal")
        self.assertNotIn("requiredPermission", collection)

    def test_403_40301_dict_body_names_the_grant(self):
        for t, key, perm, _, _ in self.each():
            response = t.transform(marker(403, BODY_40301))
            self.assert_unevaluated(response, key)
            self.assert_names_grant(response, perm)

    def test_403_40301_json_string_body(self):
        for t, key, perm, _, _ in self.each():
            response = t.transform(marker(403, json.dumps(BODY_40301)))
            self.assert_unevaluated(response, key)
            self.assert_names_grant(response, perm)

    def test_whole_input_as_json_string_and_bytes(self):
        for t, key, perm, _, _ in self.each():
            text = json.dumps(marker(403, BODY_40301))
            for payload in (text, text.encode("utf-8")):
                response = t.transform(payload)
                self.assert_unevaluated(response, key)
                self.assert_names_grant(response, perm)

    def test_nested_one_level(self):
        for t, key, perm, _, _ in self.each():
            for payload in ({"apiResponse": marker(403, BODY_40301)},
                            {"response": marker(403, BODY_40301)},
                            {"data": marker(403, BODY_40301), "validation": {"status": "passed"}},
                            {"somethingElse": marker(403, BODY_40301)}):
                response = t.transform(payload)
                self.assert_unevaluated(response, key)
                self.assert_names_grant(response, perm)

    def test_other_statuses_are_generic(self):
        for t, key, _, _, _ in self.each():
            for status in (401, 500):
                response = t.transform(marker(status, {"stat": "FAIL", "code": 40101, "message": "Invalid signature"}))
                self.assert_unevaluated(response, key)
                self.assert_generic(response, status)

    def test_403_with_a_different_body_is_generic(self):
        for t, key, _, _, _ in self.each():
            for body in ({"stat": "FAIL", "code": 40301, "message": "Something else"},
                         {"stat": "FAIL", "code": 40302, "message": "Access forbidden"},
                         "Forbidden", "<html>no</html>", None, ["x"]):
                response = t.transform(marker(403, body))
                self.assert_unevaluated(response, key)
                self.assert_generic(response, 403)

    def test_marker_without_a_status_is_generic(self):
        for t, key, _, _, _ in self.each():
            response = t.transform({"vendorErrorAsResponse": "boom"})
            self.assert_unevaluated(response, key)
            self.assertNotIn("Grant ", " ".join(response["additionalInfo"]["dataCollection"]["errors"]))

    def test_healthy_payload_unchanged(self):
        for t, key, _, ok, ok_value in self.each():
            # superAdminMfaEnrollmentPercentage never parsed JSON text; that is unchanged.
            texts = (ok,) if key == "superAdminMfaEnrollmentPercentage" else (ok, json.dumps(ok))
            for payload in texts:
                response = t.transform(payload)
                self.assertEqual(response["transformedResponse"][key], ok_value)
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertNotIn("errorCode", response["additionalInfo"]["dataCollection"])

    def test_policy_failures_still_fail(self):
        weak = {"stat": "OK", "response": {"push_enabled": False, "mobile_otp_enabled": False,
                                           "minimum_password_length": 4}}
        self.assertIs(load("authTypesAllowed").transform(weak)["transformedResponse"]["authTypesAllowed"], False)
        self.assertIs(load("confirmPasswordPolicyEnforced").transform(weak)
                      ["transformedResponse"]["confirmPasswordPolicyEnforced"], False)
        owners = {"stat": "OK", "response": [{"admin_id": "A1", "role": "Owner"}]}
        self.assertIs(load("isrbacimplemented").transform(owners)["transformedResponse"]["isRBACImplemented"], False)
        nomfa = {"stat": "OK", "response": [{"admin_id": "A1", "role": "Owner"}]}
        self.assertEqual(load("superAdminMfaEnrollmentPercentage").transform(nomfa)
                         ["transformedResponse"]["superAdminMfaEnrollmentPercentage"], 0.0)


if __name__ == "__main__":
    unittest.main()
