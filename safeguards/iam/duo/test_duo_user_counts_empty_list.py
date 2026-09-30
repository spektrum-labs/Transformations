"""Duo getUsers count keys: an empty or missing user list is not evaluated (null, dataCollection error).

bypassStatusUsersCount, lockedOutUsersCount and smsFactorEnabledUsersCount used to answer 0 on an
empty list, which the criteria read as a pass. A non-empty list is counted exactly as before.
"""
import importlib.util
import unittest
from pathlib import Path

KEYS = ("bypassStatusUsersCount", "lockedOutUsersCount", "smsFactorEnabledUsersCount")
USERS = [
    {"user_id": "DU1", "username": "a", "status": "active",
     "phones": [{"capabilities": ["push", "sms"]}]},
    {"user_id": "DU2", "username": "b", "status": "bypass", "phones": []},
    {"user_id": "DU3", "username": "c", "status": "locked out", "phones": [{"capabilities": ["push"]}]},
]
CLEAN = [{"user_id": "DU4", "username": "d", "status": "active", "phones": [{"capabilities": ["push"]}]}]


def load(key):
    spec = importlib.util.spec_from_file_location("duo_" + key, Path(__file__).with_name(key + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoUserCountEmptyListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = {k: load(k) for k in KEYS}

    def test_empty_or_missing_list_is_not_evaluated(self):
        for key in KEYS:
            for payload in ({"response": []}, {"result": {"response": []}}, [], {}, None, "",
                            {"response": [], "metadata": {"total_objects": 0}}, {"response": "x"},
                            {"stat": "FAIL", "code": 40301}):
                with self.subTest(key=key, payload=payload):
                    out = self.t[key].transform(payload)
                    self.assertIsNone(out["transformedResponse"][key])
                    self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                    self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_non_empty_list_is_counted(self):
        expected = {"bypassStatusUsersCount": 1, "lockedOutUsersCount": 1, "smsFactorEnabledUsersCount": 1}
        for key in KEYS:
            for payload in ({"response": USERS}, {"result": {"response": USERS}}, USERS):
                with self.subTest(key=key, payload=str(payload)[:30]):
                    out = self.t[key].transform(payload)
                    self.assertEqual(out["transformedResponse"][key], expected[key])
                    self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_measured_zero_over_non_empty_list(self):
        for key in KEYS:
            with self.subTest(key=key):
                out = self.t[key].transform({"response": CLEAN})
                self.assertEqual(out["transformedResponse"][key], 0)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")


if __name__ == "__main__":
    unittest.main()
