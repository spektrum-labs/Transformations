"""Duo user-read and API-access checks: a read that measured nothing is Not evaluated, never False or 0.0.

Seven transforms read GET /admin/v1/users (isMFAEnforcedForUsers, islifecyclemanagementenabled,
mfaDeviceEnrollmentPercentage, desktopAuthenticatorEnrollmentPercentage,
webAuthnCredentialAdoptionPercentage) or one user's bypass_codes / webauthncredentials
(hasEmergencyAccessCodeAPIAccess, hasFIDOAuthenticatorManagementAPIAccess). They used to answer False or 0.0
(or, for the two access checks, False or True) for an empty body, None, an error body, a non-list
response or an empty user list. An empty list is what a failed read defaults to and a quiet tenant looks the
same, so it measured nothing. Each of those is now Not evaluated: every value None and
additionalInfo.dataCollection.status "error". A real read that shows the condition absent stays measured.
The 403 / 40301 refusal marker is covered for all seven in test_duo_vendor_error_marker.py.
Synthetic data only.
"""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent

BODY_40301 = {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}


def load(name):
    spec = importlib.util.spec_from_file_location("duo_ne_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def user(uid, **fields):
    base = {"user_id": uid, "username": "user-" + uid, "status": "active", "is_enrolled": True,
            "last_directory_sync": None, "phones": [], "tokens": [], "u2ftokens": [],
            "webauthncredentials": [], "desktop_authenticators": []}
    base.update(fields)
    return base


def users_body(*users):
    return {"stat": "OK", "response": list(users), "metadata": {"next_offset": None, "total_objects": len(users)}}


HEALTHY_USERS = users_body(
    user("DU1", last_directory_sync=1790000000, phones=[{"phone_id": "DP1"}],
         webauthncredentials=[{"webauthnkey": "WK1"}], desktop_authenticators=[{"did": "DA1"}]),
    user("DU2", phones=[{"phone_id": "DP2"}]),
)
HEALTHY_BYPASS = {"stat": "OK", "response": [{"bypass_code_id": "BC1", "user_id": "DU1", "remaining_uses": 1}],
                  "metadata": {"next_offset": None, "total_objects": 1}}
HEALTHY_WEBAUTHN = {"stat": "OK", "response": [{"webauthnkey": "WK1", "credential_name": "key"}],
                    "metadata": {"next_offset": None, "total_objects": 1}}
EMPTY_OK = {"stat": "OK", "response": [], "metadata": {"next_offset": None, "total_objects": 0}}

USER_CHECKS = {
    "isMFAEnforcedForUsers": ("isMFAEnforcedForUsers", HEALTHY_USERS),
    "islifecyclemanagementenabled": ("isLifeCycleManagementEnabled", HEALTHY_USERS),
    "mfaDeviceEnrollmentPercentage": ("mfaDeviceEnrollmentPercentage", HEALTHY_USERS),
    "desktopAuthenticatorEnrollmentPercentage": ("desktopAuthenticatorEnrollmentPercentage", HEALTHY_USERS),
    "webAuthnCredentialAdoptionPercentage": ("webAuthnCredentialAdoptionPercentage", HEALTHY_USERS),
}
ACCESS_CHECKS = {
    "hasEmergencyAccessCodeAPIAccess": ("hasEmergencyAccessCodeAPIAccess", HEALTHY_BYPASS),
    "hasFIDOAuthenticatorManagementAPIAccess": ("hasFIDOAuthenticatorManagementAPIAccess", HEALTHY_WEBAUTHN),
}

# Bodies that hold no usable read, for every one of the seven.
NOTHING_READ = [
    ("empty object", {}),
    ("None", None),
    ("empty string", ""),
    ("empty bytes", b""),
    ("not JSON", "not json"),
    ("a number", 42),
    ("empty list", []),
    ("empty response list", {"response": []}),
    ("empty list nested in result", {"result": {"response": []}}),
    ("response is text", {"response": "x"}),
    ("response is an object", {"response": {"a": 1}}),
    ("plain 40301 body", BODY_40301),
    ("plain 40301 body in apiResponse", {"apiResponse": BODY_40301}),
    ("plain 40301 body in data", {"data": BODY_40301, "validation": {"status": "passed"}}),
    ("FAIL envelope with empty list", {"stat": "FAIL", "response": []}),
    ("error flag", {"error": "boom", "response": []}),
    ("list of text", ["x"]),
    ("empty JSON text", "{}"),
    ("empty JSON bytes", b"{}"),
]


class NotEvaluatedMixin:
    def assert_not_evaluated(self, out, key, healthy):
        result = out["transformedResponse"]
        self.assertIn(key, result)
        for k in result:
            self.assertIsNone(result[k], k)
        # every key the healthy path returns is present and None
        self.assertEqual(set(result), set(healthy["transformedResponse"]))
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])
        self.assertIn("Grant resource - Read", " ".join(out["additionalInfo"]["evaluation"]["recommendations"]))

    def assert_measured(self, out, key, value, count_key=None, count=None):
        self.assertEqual(out["transformedResponse"][key], value)
        self.assertIs(type(out["transformedResponse"][key]), type(value))
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertNotIn("errorCode", out["additionalInfo"]["dataCollection"])
        if count_key is not None:
            self.assertEqual(out["transformedResponse"][count_key], count)


class NothingReadTests(NotEvaluatedMixin, unittest.TestCase):
    def test_user_checks_are_not_evaluated(self):
        for name, (key, ok) in USER_CHECKS.items():
            t = load(name)
            healthy = t.transform(ok)
            for label, payload in NOTHING_READ:
                with self.subTest(check=name, body=label):
                    self.assert_not_evaluated(t.transform(payload), key, healthy)

    def test_access_checks_are_not_evaluated(self):
        for name, (key, ok) in ACCESS_CHECKS.items():
            t = load(name)
            healthy = t.transform(ok)
            for label, payload in NOTHING_READ:
                with self.subTest(check=name, body=label):
                    self.assert_not_evaluated(t.transform(payload), key, healthy)

    def test_empty_user_list_with_duo_ok_envelope_is_not_evaluated(self):
        # A failed read defaults to an empty list and a quiet tenant looks the same: no proof either way.
        for name, (key, ok) in USER_CHECKS.items():
            t = load(name)
            healthy = t.transform(ok)
            for payload in (EMPTY_OK, {"data": EMPTY_OK, "validation": {"status": "passed"}}, json.dumps(EMPTY_OK)):
                with self.subTest(check=name):
                    self.assert_not_evaluated(t.transform(payload), key, healthy)

    def test_objects_that_are_not_users_are_not_evaluated(self):
        for name, (key, ok) in USER_CHECKS.items():
            t = load(name)
            healthy = t.transform(ok)
            for label, payload in (("truncation stub", [{"_truncated": True}]),
                                   ("no identity", [{"status": "active"}]),
                                   ("text entries", {"response": ["a", "b"]}),
                                   ("nulls", {"response": [None, None]})):
                with self.subTest(check=name, body=label):
                    self.assert_not_evaluated(t.transform(payload), key, healthy)

    def test_enriched_input_with_failed_validation_is_not_evaluated_for_access_checks(self):
        for name, (key, ok) in ACCESS_CHECKS.items():
            t = load(name)
            healthy = t.transform(ok)
            payload = {"data": EMPTY_OK, "validation": {"status": "failed", "errors": ["bad"]}}
            self.assert_not_evaluated(t.transform(payload), key, healthy)


class MeasuredUserReadsTests(NotEvaluatedMixin, unittest.TestCase):
    """A read that returned users and shows the condition absent is still a measured False or 0.0."""

    def test_mfa_enforced_for_users(self):
        t = load("isMFAEnforcedForUsers")
        key = "isMFAEnforcedForUsers"
        half = users_body(user("DU1"), user("DU2", is_enrolled=False))
        out = t.transform(half)
        self.assert_measured(out, key, False, "mfaEnforcedUserPercentage", 50.0)
        self.assertEqual(out["transformedResponse"]["unenrolledUserCount"], 1)
        bypass = t.transform(users_body(user("DU1"), user("DU2", status="bypass")))
        self.assert_measured(bypass, key, False, "bypassUserCount", 1)
        none_enrolled = t.transform(users_body(user("DU1", is_enrolled=False)))
        self.assert_measured(none_enrolled, key, False, "mfaEnforcedUserPercentage", 0.0)
        all_inactive = t.transform(users_body(user("DU1", status="disabled"), user("DU2", status="locked out")))
        self.assert_measured(all_inactive, key, False, "activeUsers", 0)
        self.assert_measured(t.transform(users_body(user("DU1"), user("DU2"))), key, True,
                             "mfaEnforcedUserPercentage", 100.0)

    def test_lifecycle_management(self):
        t = load("islifecyclemanagementenabled")
        key = "isLifeCycleManagementEnabled"
        by_hand = t.transform(users_body(user("DU1"), user("DU2")))  # last_directory_sync present and null
        self.assert_measured(by_hand, key, False, "directorySyncedUserPercentage", 0.0)
        self.assertEqual(by_hand["transformedResponse"]["activeUsers"], 2)
        synced = t.transform(users_body(user("DU1", last_directory_sync=1790000000), user("DU2")))
        self.assert_measured(synced, key, True, "directorySyncedUserPercentage", 50.0)

    def test_lifecycle_users_without_the_sync_field_are_not_evaluated(self):
        t = load("islifecyclemanagementenabled")
        bare = {"stat": "OK", "response": [{"user_id": "DU1", "username": "a", "status": "active"}]}
        healthy = t.transform(HEALTHY_USERS)
        self.assert_not_evaluated(t.transform(bare), "isLifeCycleManagementEnabled", healthy)

    def test_mfa_device_enrollment(self):
        t = load("mfaDeviceEnrollmentPercentage")
        key = "mfaDeviceEnrollmentPercentage"
        none = t.transform(users_body(user("DU1", is_enrolled=False), user("DU2", is_enrolled=False)))
        self.assert_measured(none, key, 0.0, "activeUsers", 2)
        half = t.transform(users_body(user("DU1", phones=[{"phone_id": "P"}]), user("DU2", is_enrolled=False)))
        self.assert_measured(half, key, 50.0, "usersWithEnrolledDevice", 1)
        inactive = t.transform(users_body(user("DU1", status="disabled")))
        self.assert_measured(inactive, key, 0.0, "activeUsers", 0)

    def test_mfa_device_enrollment_users_with_no_device_fields_are_not_evaluated(self):
        t = load("mfaDeviceEnrollmentPercentage")
        bare = {"stat": "OK", "response": [{"user_id": "DU1", "username": "a", "status": "active"},
                                           {"user_id": "DU2", "username": "b", "status": "active"}]}
        self.assert_not_evaluated(t.transform(bare), "mfaDeviceEnrollmentPercentage", t.transform(HEALTHY_USERS))
        # one user carrying the fields keeps the measurement; the bare one counts as without a device
        mixed = {"stat": "OK", "response": [{"user_id": "DU1", "status": "active"}, user("DU2", is_enrolled=True)]}
        self.assert_measured(t.transform(mixed), "mfaDeviceEnrollmentPercentage", 50.0, "activeUsers", 2)

    def test_desktop_authenticator_enrollment(self):
        t = load("desktopAuthenticatorEnrollmentPercentage")
        key = "desktopAuthenticatorEnrollmentPercentage"
        none = t.transform(users_body(user("DU1"), user("DU2")))
        self.assert_measured(none, key, 0.0, "totalUsers", 2)
        half = t.transform(users_body(user("DU1", desktop_authenticators=[{"did": "DA1"}]), user("DU2")))
        self.assert_measured(half, key, 50.0, "usersWithDesktopAuthenticator", 1)

    def test_desktop_authenticator_users_without_the_field_are_not_evaluated(self):
        t = load("desktopAuthenticatorEnrollmentPercentage")
        bare = {"stat": "OK", "response": [{"user_id": "DU1", "username": "a", "status": "active"}]}
        self.assert_not_evaluated(t.transform(bare), "desktopAuthenticatorEnrollmentPercentage",
                                  t.transform(HEALTHY_USERS))

    def test_webauthn_adoption(self):
        t = load("webAuthnCredentialAdoptionPercentage")
        key = "webAuthnCredentialAdoptionPercentage"
        none = t.transform(users_body(user("DU1"), user("DU2")))
        self.assert_measured(none, key, 0.0, "totalUsers", 2)
        half = t.transform(users_body(user("DU1", webauthncredentials=[{"webauthnkey": "WK1"}]), user("DU2")))
        self.assert_measured(half, key, 50.0, "usersWithWebAuthnCredentials", 1)

    def test_webauthn_users_without_the_field_are_not_evaluated(self):
        t = load("webAuthnCredentialAdoptionPercentage")
        bare = {"stat": "OK", "response": [{"user_id": "DU1", "username": "a", "status": "active"}]}
        self.assert_not_evaluated(t.transform(bare), "webAuthnCredentialAdoptionPercentage",
                                  t.transform(HEALTHY_USERS))

    def test_user_list_shapes_all_measure(self):
        body = users_body(user("DU1"), user("DU2", is_enrolled=False))
        for name, (key, _) in USER_CHECKS.items():
            t = load(name)
            for payload in (body, body["response"], {"result": body}, {"apiResponse": body},
                            {"data": body, "validation": {"status": "passed"}}, json.dumps(body),
                            json.dumps(body).encode("utf-8")):
                with self.subTest(check=name, shape=type(payload).__name__):
                    out = t.transform(payload)
                    self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
                    self.assertIsNotNone(out["transformedResponse"][key])


class AccessChecksReadTests(NotEvaluatedMixin, unittest.TestCase):
    """Duo answered a successful read: access is shown, including an empty list under Duo's OK envelope."""

    def test_populated_read_passes(self):
        for name, (key, ok) in ACCESS_CHECKS.items():
            count_key = "bypassCodeCount" if "Emergency" in name else "credentialsReturned"
            t = load(name)
            for payload in (ok, ok["response"], {"result": ok}, {"data": ok, "validation": {"status": "passed"}},
                            json.dumps(ok), json.dumps(ok).encode("utf-8")):
                with self.subTest(check=name, shape=type(payload).__name__):
                    out = t.transform(payload)
                    self.assert_measured(out, key, True, count_key, 1)
                    self.assertTrue(out["additionalInfo"]["evaluation"]["passReasons"])

    def test_empty_list_under_the_ok_envelope_is_a_measured_pass(self):
        for name, (key, _) in ACCESS_CHECKS.items():
            count_key = "bypassCodeCount" if "Emergency" in name else "credentialsReturned"
            t = load(name)
            for payload in (EMPTY_OK, {"stat": "OK", "response": []},
                            {"data": EMPTY_OK, "validation": {"status": "passed"}}, json.dumps(EMPTY_OK)):
                with self.subTest(check=name, shape=type(payload).__name__):
                    self.assert_measured(t.transform(payload), key, True, count_key, 0)

    def test_empty_list_without_proof_is_not_evaluated(self):
        for name, (key, ok) in ACCESS_CHECKS.items():
            t = load(name)
            healthy = t.transform(ok)
            for payload in ([], {"response": []}, {"result": {"response": []}}, {"stat": "OK"},
                            {"data": [], "validation": {"status": "passed"}}):
                with self.subTest(check=name, body=str(payload)):
                    self.assert_not_evaluated(t.transform(payload), key, healthy)


if __name__ == "__main__":
    unittest.main()
