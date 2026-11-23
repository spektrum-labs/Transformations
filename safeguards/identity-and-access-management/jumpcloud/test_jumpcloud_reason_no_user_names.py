"""JumpCloud user-count transforms name example users by JumpCloud user id, never by username or email.

Reasons are shown to customers and kept in posture evidence. Synthetic users only.
"""
import importlib.util
import json
import unittest
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location("nouser_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def user(i, **extra):
    record = {"_id": "uid-" + str(i), "username": "synth.person" + str(i), "email": "synth.person" + str(i) + "@example.test"}
    record.update(extra)
    return record


CASES = {
    "lockedOutUsersCount": [user(1, account_locked=True), user(2, account_locked=False)],
    "suspendedUsersCount": [user(1, suspended=True), user(2)],
    "inactiveMfaFactorsCount": [user(1, mfa={"configured": True}, mfaEnrollment={"overallStatus": "ENROLLED", "smsStatus": "NOT_ENROLLED"}), user(2)],
}


class ReasonNamesNoUser(unittest.TestCase):
    def test_examples_use_user_id(self):
        for name, users in CASES.items():
            text = json.dumps(load(name).transform({"results": users, "totalCount": len(users)}))
            self.assertNotIn("synth.person", text, name)
            self.assertIn("uid-1", text, name)


if __name__ == "__main__":
    unittest.main()
