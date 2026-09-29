"""isAppConsentRestricted reads Cloud Identity Policy API api_controls settings (getApiControlsPolicies).

Fixture shape mirrors Spektrum's Workspace read of 2026-09-28 (ids replaced): four SYSTEM api_controls
policies on the root org unit; unconfigured third-party apps at ACCESS_LEVEL_UNSPECIFIED.
"""
import copy
import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isappconsentrestricted.py")
KEY = "isAppConsentRestricted"


def load():
    spec = importlib.util.spec_from_file_location("isappconsentrestricted", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(kind, value, ou="orgUnits/root", ptype="SYSTEM"):
    return {"name": "policies/x", "customer": "customers/C0", "type": ptype,
            "policyQuery": {"orgUnit": ou, "sortOrder": 1}, "setting": {"type": "settings/api_controls." + kind, "value": value}}


REAL = {"result": {"apiResponse": {"policies": [
    policy("custom_user_message", {"errorText": ""}),
    policy("internal_apps", {"trustInternalApps": True}),
    policy("unconfigured_third_party_apps", {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED",
                                             "accessLevelUnder18": "ACCESS_LEVEL_UNDER18_UNSPECIFIED"}),
    policy("app_approval_requests", {"allowedForAll": "ENABLED"}),
]}}}


class AppConsentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def out(self, payload):
        return self.t.transform(payload)["transformedResponse"]

    def test_real_shape_unrestricted_fails(self):
        out = self.out(REAL)
        self.assertIs(out[KEY], False)
        self.assertEqual(out["appConsentRestrictedPolicyPercentage"], 0.0)

    def test_flipped_to_block_all_passes(self):
        data = copy.deepcopy(REAL)
        data["result"]["apiResponse"]["policies"][2]["setting"]["value"]["accessLevel"] = "BLOCK_ALL"
        out = self.out(data)
        self.assertIs(out[KEY], True)
        self.assertEqual(out["appConsentRestrictedPolicyPercentage"], 100.0)

    def test_sign_in_only_root_with_open_child_ou_fails(self):
        data = copy.deepcopy(REAL)
        pols = data["result"]["apiResponse"]["policies"]
        pols[2]["setting"]["value"]["accessLevel"] = "ALLOW_SIGN_IN_ONLY"
        pols.append(policy("unconfigured_third_party_apps", {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED"}, "orgUnits/eng", "ADMIN"))
        out = self.out(data)
        self.assertIs(out[KEY], False)
        self.assertEqual(out["appConsentRestrictedPolicyPercentage"], 50.0)

    def test_setting_absent_fails_closed(self):
        data = copy.deepcopy(REAL)
        del data["result"]["apiResponse"]["policies"][2]
        self.assertIs(self.out(data)[KEY], False)

    def test_no_evidence_fails_closed(self):
        for body in [{}, None, "{}", [], {"policies": []}, {"statusCode": 401, "error": "Unauthorized"},
                     {"statusCode": 403, "error": "Forbidden"},
                     {"error": {"code": 403, "message": "Request had insufficient authentication scopes.", "status": "PERMISSION_DENIED"}}]:
            self.assertIs(self.out(body)[KEY], False, body)


if __name__ == "__main__":
    unittest.main()
