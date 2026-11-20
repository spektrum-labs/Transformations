"""CrashPlan licence check does not copy the API user's username or email into its result. Synthetic values only."""
import importlib.util
import json
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("crashplan_licence", Path(__file__).with_name("confirmedlicensepurchased.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NoUserIdentity(unittest.TestCase):
    def test_result_has_no_username_or_email(self):
        out = module.transform({"userId": "u-1", "username": "synth.person", "email": "synth.person@example.test", "status": "Active"})
        self.assertNotIn("synth.person", json.dumps(out))


if __name__ == "__main__":
    unittest.main()
