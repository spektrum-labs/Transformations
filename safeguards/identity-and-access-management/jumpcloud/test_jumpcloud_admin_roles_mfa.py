"""isRBACImplemented and superAdminMfaEnrollmentPercentage read the JumpCloud administrator list (GET /api/users).

Fixture: synthetic tenant A, in the shape Get-JCAdmin documents (results + totalCount; roleName, enableMultiFactor,
totpEnrolled, suspended). Booleans are also tried as "true"/"false" strings, which Integration-Service can return.
"""
import copy
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def admin(n, role, totp=True, mfa=True, suspended=False):
    return {"_id": "adm" + str(n), "email": "admin" + str(n) + "@tenant-a.example", "firstname": "A", "lastname": str(n),
            "roleName": role, "enableMultiFactor": mfa, "totpEnrolled": totp, "suspended": suspended,
            "organization": "org-a"}


REAL = {"totalCount": 5, "results": [
    admin(1, "Administrator With Billing"),
    admin(2, "Administrator With Billing"),
    admin(3, "Administrator", totp=False, mfa=True),
    admin(4, "Help Desk", totp=False, mfa=False),
    admin(5, "Read Only", totp=False, mfa=False),
]}

EMPTY_BODIES = [{}, None, "", "{}", "null", [], {"results": []}, {"value": []},
                {"message": "Unauthorized"}, {"error": "Forbidden", "status": 403},
                {"results": "nope", "totalCount": 1}]


def ts_at_least(value, threshold):
    """Token-Service greaterThan / greaterThanOrEqual: int(float(value)) >= int(float(threshold))."""
    try:
        return int(float(value)) >= int(float(threshold))
    except Exception:
        return False


def stringify(body):
    out = copy.deepcopy(body)
    out["totalCount"] = str(out["totalCount"])
    for a in out["results"]:
        for k in ("enableMultiFactor", "totpEnrolled", "suspended"):
            a[k] = "true" if a[k] else "false"
    return out


class Base(unittest.TestCase):
    NAME = None

    @classmethod
    def setUpClass(cls):
        cls.t = load(cls.NAME)

    def full(self, body):
        return self.t.transform(body)

    def value(self, body):
        return self.full(body)["transformedResponse"][self.NAME]

    def assert_unevaluated(self, body):
        full = self.full(body)
        self.assertIsNone(full["transformedResponse"][self.NAME], body)
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error", body)
        self.assertTrue(full["additionalInfo"]["dataCollection"]["errors"], body)


class RbacTests(Base):
    NAME = "isRBACImplemented"

    def test_real_shape_scoped_role_in_use_passes(self):
        full = self.full(REAL)
        self.assertIs(full["transformedResponse"][self.NAME], True)
        self.assertEqual(full["transformedResponse"]["scopedAdminCount"], 1)
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")

    def test_flipped_all_full_admin_is_flat_access(self):
        body = copy.deepcopy(REAL)
        body["results"][3]["roleName"] = "Administrator"
        self.assertIs(self.value(body), False)

    def test_read_only_alone_is_not_evidence(self):
        # The integration's own Read Only service admin must not satisfy the check by itself.
        body = {"totalCount": 2, "results": [admin(1, "Administrator With Billing"), admin(2, "Read Only")]}
        self.assertIs(self.value(body), False)

    def test_suspended_scoped_admin_does_not_count(self):
        body = copy.deepcopy(REAL)
        body["results"][3]["suspended"] = True
        self.assertIs(self.value(body), False)

    def test_custom_and_multi_role(self):
        body = {"totalCount": 2, "results": [admin(1, "Administrator With Billing"), admin(2, None)]}
        body["results"][1]["roleNames"] = ["Device Ops (custom)"]
        self.assertIs(self.value(body), True)
        body["results"][1]["roleNames"] = ["Help Desk", "Administrator"]
        self.assertIs(self.value(body), False)

    def test_string_booleans(self):
        self.assertIs(self.value(stringify(REAL)), True)

    def test_unreadable_role_blocks_a_false(self):
        body = {"totalCount": 2, "results": [admin(1, "Administrator"), admin(2, None)]}
        self.assert_unevaluated(body)

    def test_empty_none_and_error_bodies_are_unevaluated(self):
        for body in EMPTY_BODIES:
            self.assert_unevaluated(body)

    def test_partial_read_and_missing_total_are_unevaluated(self):
        body = copy.deepcopy(REAL)
        body["totalCount"] = 150
        self.assert_unevaluated(body)
        body = copy.deepcopy(REAL)
        del body["totalCount"]
        self.assert_unevaluated(body)

    def test_all_suspended_is_unevaluated(self):
        body = {"totalCount": 1, "results": [admin(1, "Help Desk", suspended=True)]}
        self.assert_unevaluated(body)

    def test_wrapped_and_bytes_input(self):
        self.assertIs(self.value({"apiResponse": REAL}), True)
        import json
        self.assertIs(self.value(json.dumps(REAL).encode("utf-8")), True)

    def test_transformation_error_is_unevaluated(self):
        self.assert_unevaluated(b"\xff not json")


class SuperAdminMfaTests(Base):
    NAME = "superAdminMfaEnrollmentPercentage"

    def test_real_shape_one_unenrolled_administrator_fails_100(self):
        full = self.full(REAL)
        out = full["transformedResponse"]
        self.assertEqual(out[self.NAME], 66.6)  # 2 of 3 full admins, rounded down
        self.assertEqual(out["superAdminCount"], 3)
        self.assertEqual(out["administratorWithBillingMfaPercentage"], 100.0)
        self.assertFalse(ts_at_least(out[self.NAME], "100"))
        self.assertFalse(ts_at_least(out[self.NAME], "100.0"))
        self.assertTrue(any("required but not yet enrolled" in r
                            for r in full["additionalInfo"]["evaluation"]["failReasons"]))

    def test_flipped_all_enrolled_is_100(self):
        body = copy.deepcopy(REAL)
        body["results"][2]["totpEnrolled"] = True
        out = self.full(body)["transformedResponse"]
        self.assertEqual(out[self.NAME], 100.0)
        self.assertTrue(ts_at_least(out[self.NAME], "100"))

    def test_scoped_and_suspended_admins_are_out_of_scope(self):
        body = copy.deepcopy(REAL)
        body["results"][2]["suspended"] = True  # the unenrolled Administrator
        self.assertEqual(self.value(body), 100.0)

    def test_never_rounds_up_to_100(self):
        results = [admin(i, "Administrator") for i in range(1, 2001)]
        results[0]["totpEnrolled"] = False
        value = self.value({"totalCount": 2000, "results": results})
        self.assertEqual(value, 99.9)
        self.assertFalse(ts_at_least(value, "100"))

    def test_required_flag_alone_is_not_enrolment(self):
        body = {"totalCount": 1, "results": [admin(1, "Administrator With Billing", totp=False, mfa=True)]}
        self.assertEqual(self.value(body), 0.0)

    def test_string_booleans(self):
        self.assertEqual(self.value(stringify(REAL)), 66.6)

    def test_missing_totp_field_is_unevaluated(self):
        body = copy.deepcopy(REAL)
        del body["results"][0]["totpEnrolled"]
        self.assert_unevaluated(body)

    def test_unreadable_role_is_unevaluated(self):
        body = copy.deepcopy(REAL)
        body["results"][4]["roleName"] = None
        self.assert_unevaluated(body)

    def test_no_full_admin_is_unevaluated(self):
        body = {"totalCount": 1, "results": [admin(1, "Read Only")]}
        self.assert_unevaluated(body)

    def test_empty_none_and_error_bodies_are_unevaluated(self):
        for body in EMPTY_BODIES:
            self.assert_unevaluated(body)

    def test_partial_read_is_unevaluated(self):
        body = copy.deepcopy(REAL)
        body["totalCount"] = "101"
        self.assert_unevaluated(body)

    def test_value_is_never_a_boolean(self):
        for body in [REAL, {}, None]:
            self.assertNotIsInstance(self.value(body), bool)

    def test_no_admin_email_in_output(self):
        import json
        for name in ("isRBACImplemented", "superAdminMfaEnrollmentPercentage"):
            self.assertNotIn("@tenant-a.example", json.dumps(load(name).transform(REAL)))

    def test_transformation_error_is_unevaluated(self):
        self.assert_unevaluated(b"\xff not json")


if __name__ == "__main__":
    unittest.main()
