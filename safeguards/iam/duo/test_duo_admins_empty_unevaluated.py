"""Duo getAdmins keys: an empty, error or unreadable body is not evaluated (all None, dataCollection error).

A Duo account always has an Owner and getAdmins' returnSpec defaults an unreadable body to an empty
value, so isRBACImplemented must not say False and superAdminMfaEnrollmentPercentage must not say 0
from it. Real administrator lists keep their answers.
"""
import importlib.util
import json
import unittest
from pathlib import Path

RBAC = "isrbacimplemented"
SUPER = "superAdminMfaEnrollmentPercentage"
KEYS = {RBAC: ["isRBACImplemented", "adminCount", "ownerAdminPercentage"],
        SUPER: ["superAdminMfaEnrollmentPercentage", "totalSuperAdmins", "enrolledSuperAdmins"]}

OWNER = {"admin_id": "DA1", "name": "Olive Owner", "role": "Owner",
         "phone_details": [{"activated": True}], "webauthncredentials": [], "hardtoken": None}
ADMIN_NO_MFA = {"admin_id": "DA2", "name": "Ada Admin", "role": "Administrator",
                "phone_details": [{"activated": False}], "webauthncredentials": []}
HELPDESK = {"admin_id": "DA3", "name": "Hal Help", "role": "Help Desk", "phone_details": []}
ONLY_OWNERS = [OWNER, dict(OWNER, admin_id="DA4")]
REAL = [OWNER, ADMIN_NO_MFA, HELPDESK]

UNREADABLE = [
    {"response": []}, {"result": {"response": []}}, [], {}, None, "", b"", 42, "{bad json", "[]", "{}",
    b"\xff\xfe", {"stat": "FAIL", "code": 40002, "message": "Invalid request"},
    {"error": "boom"}, {"statusCode": 500, "body": "x"}, {"response": "x"},
    {"response": [{"name": "no id, no role"}]}, {"response": ["a", 3, None]},
]


def load(name):
    spec = importlib.util.spec_from_file_location("duo_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoAdminsUnevaluatedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = {k: load(k) for k in KEYS}

    def assert_unevaluated(self, out, name):
        self.assertEqual(sorted(out["transformedResponse"]), sorted(KEYS[name]))
        for k in KEYS[name]:
            self.assertIsNone(out["transformedResponse"][k])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_unreadable_or_empty_is_not_evaluated(self):
        for name in KEYS:
            for payload in UNREADABLE:
                with self.subTest(name=name, payload=repr(payload)[:40]):
                    self.assert_unevaluated(self.t[name].transform(payload), name)

    def test_exception_path_is_not_evaluated(self):
        class Boom(dict):
            def get(self, *a, **k):
                raise RuntimeError("boom")

            def __contains__(self, k):
                raise RuntimeError("boom")

        for name in KEYS:
            with self.subTest(name=name):
                self.assert_unevaluated(self.t[name].transform({"response": [Boom(admin_id="x", role="Owner")]}), name)
                self.assert_unevaluated(self.t[name].transform(Boom()), name)

    def test_rbac_real_lists_keep_their_answers(self):
        t = self.t[RBAC]
        for payload in ({"response": REAL}, {"result": {"response": REAL}}, REAL, json.dumps({"response": REAL}),
                        json.dumps({"response": REAL}).encode()):
            with self.subTest(payload=str(payload)[:30]):
                out = t.transform(payload)
                r = out["transformedResponse"]
                self.assertIs(r["isRBACImplemented"], True)
                self.assertEqual(r["adminCount"], 3)
                self.assertEqual(r["ownerAdminPercentage"], 33.3)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        out = t.transform({"response": ONLY_OWNERS})
        self.assertIs(out["transformedResponse"]["isRBACImplemented"], False)
        self.assertEqual(out["transformedResponse"]["ownerAdminPercentage"], 100.0)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        # an admin with an id but no role is a measured answer, as before
        out = t.transform({"response": [{"admin_id": "DA9"}]})
        self.assertIs(out["transformedResponse"]["isRBACImplemented"], False)
        self.assertEqual(out["transformedResponse"]["adminCount"], 1)

    def test_super_admin_real_lists_keep_their_answers(self):
        t = self.t[SUPER]
        for payload in ({"response": REAL}, {"result": {"response": REAL}}, REAL, json.dumps({"response": REAL}),
                        json.dumps(REAL).encode()):
            with self.subTest(payload=str(payload)[:30]):
                out = t.transform(payload)
                self.assertEqual(out["transformedResponse"], {
                    "superAdminMfaEnrollmentPercentage": 50.0, "totalSuperAdmins": 2, "enrolledSuperAdmins": 1})
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        out = t.transform({"response": [OWNER, dict(ADMIN_NO_MFA, phone_details=[], webauthncredentials=[{"id": 1}])]})
        self.assertEqual(out["transformedResponse"]["superAdminMfaEnrollmentPercentage"], 100.0)
        out = t.transform({"response": [dict(OWNER, phone_details=[]), ADMIN_NO_MFA]})
        self.assertEqual(out["transformedResponse"]["superAdminMfaEnrollmentPercentage"], 0.0)
        self.assertEqual(out["transformedResponse"]["totalSuperAdmins"], 2)

    def test_super_admin_zero_denominator_over_real_admins_is_a_measured_zero(self):
        out = self.t[SUPER].transform({"response": [HELPDESK]})
        self.assertEqual(out["transformedResponse"], {
            "superAdminMfaEnrollmentPercentage": 0, "totalSuperAdmins": 0, "enrolledSuperAdmins": 0})
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])


if __name__ == "__main__":
    unittest.main()
