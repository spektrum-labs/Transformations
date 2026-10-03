"""isConditionalAccessEnabled reads Okta sign-in policies and rules from getMfaPolicyRules.

Fixture shape mirrors Spektrum's tenant read of 2026-09-28 (ids replaced): five active app authentication
policies; one ('FastPass Passwordless Registered Devices') allows only registered devices and denies
everything else in its catch-all.
"""
import copy
import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isconditionalaccessenabled.py")
KEY = "isConditionalAccessEnabled"


def load():
    spec = importlib.util.spec_from_file_location("isconditionalaccessenabled", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rule(name, access="ALLOW", mode="2FA", conditions=None, system=False, priority=0):
    return {"name": name, "status": "ACTIVE", "system": system, "priority": priority, "conditions": conditions,
            "actions": {"appSignOn": {"access": access, "verificationMethod": {"type": "ASSURANCE", "factorMode": mode}}}}


def catch_all(access="ALLOW", mode="2FA"):
    return rule("Catch-all Rule", access, mode, None, True, 99)


ANYWHERE = {"network": {"connection": "ANYWHERE"}}
DEVICE = {"network": {"connection": "ANYWHERE"}, "device": {"registered": True, "managed": False}}
ZONE = {"network": {"connection": "ZONE", "exclude": ["nzoCorp"]}}

REAL = {"result": {
    "signOnPolicies": [{"id": "p1", "name": "Default Policy", "status": "ACTIVE", "system": True}],
    "signOnRules": [[{"name": "Default Rule", "status": "ACTIVE", "system": True, "priority": 1,
                      "conditions": ANYWHERE, "actions": {"signon": {"access": "ALLOW", "requireFactor": False}}}]],
    "accessPolicies": [
        {"id": "a1", "name": "Okta Admin Console", "status": "ACTIVE", "_embedded": {"resourceType": "APP"}},
        {"id": "a2", "name": "Okta Dashboard", "status": "ACTIVE", "_embedded": {"resourceType": "APP"}},
        {"id": "a3", "name": "Okta Browser Plugin", "status": "ACTIVE", "_embedded": {"resourceType": "APP"}},
        {"id": "a4", "name": "Any two factors", "status": "ACTIVE", "_embedded": {"resourceType": "APP"}},
        {"id": "a5", "name": "Okta Account Management Policy", "status": "ACTIVE",
         "_embedded": {"resourceType": "END_USER_ACCOUNT_MANAGEMENT"}},
        {"id": "a6", "name": "FastPass Passwordless Registered Devices", "status": "ACTIVE", "_embedded": {"resourceType": "APP"}},
    ],
    "accessRules": [
        [rule("Admin App Policy", conditions=ANYWHERE), catch_all()],
        [catch_all()],
        [catch_all()],
        [catch_all()],
        [rule("Password Expiry Rule", mode="1FA", conditions=ANYWHERE), catch_all(mode="2FA_If_Possible")],
        [rule("Passwordless for Managed Devices", conditions=DEVICE), catch_all(access="DENY")],
    ],
}}


class ConditionalAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def out(self, payload):
        return self.t.transform(payload)["transformedResponse"]

    def test_real_shape_passes_with_percentage(self):
        out = self.out(REAL)
        self.assertIs(out[KEY], True)
        self.assertEqual(out["conditionalAccessPolicyPercentage"], 20.0)  # 1 of 5 app policies

    def test_catch_all_allow_instead_of_deny_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][5][1] = catch_all()  # allow 2FA, same as the device rule
        self.assertIs(self.out(flipped)[KEY], False)

    def test_one_factor_catch_all_is_allow_all(self):
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][5] = [rule("Deny off-network", access="DENY", conditions=ZONE), catch_all(mode="1FA")]
        self.assertIs(self.out(data)[KEY], False)

    def test_zone_deny_with_two_factor_catch_all_passes(self):
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][5] = [rule("Deny off-network", access="DENY", conditions=ZONE), catch_all()]
        self.assertIs(self.out(data)[KEY], True)

    def test_conditions_without_context_do_not_count(self):
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][5] = [rule("Anywhere", conditions=ANYWHERE), catch_all(access="DENY")]
        self.assertIs(self.out(data)[KEY], False)

    def test_classic_zone_requires_factor(self):
        data = {"signOnPolicies": [{"name": "Default Policy", "status": "ACTIVE"}],
                "signOnRules": [[
                    {"name": "Off network", "status": "ACTIVE", "priority": 1, "conditions": ZONE,
                     "actions": {"signon": {"access": "DENY"}}},
                    {"name": "Default Rule", "status": "ACTIVE", "system": True, "priority": 2, "conditions": ANYWHERE,
                     "actions": {"signon": {"access": "ALLOW", "requireFactor": True}}}]],
                "accessPolicies": [], "accessRules": []}
        self.assertIs(self.out(data)[KEY], True)
        data["signOnRules"][0][1]["actions"]["signon"]["requireFactor"] = False
        self.assertIs(self.out(data)[KEY], False)

    def test_no_evidence_is_unevaluated_not_failed(self):
        # A body that proves nothing is not a measurement: None with dataCollection "error", which the
        # Token-Service reads as Unevaluated. False here would read as a measured failure (red, gap).
        for body in [{}, None, "{}", [], {"statusCode": 401, "error": "Unauthorized"},
                     {"statusCode": 403, "error": "Forbidden"},
                     {"errorCode": "E0000006", "errorSummary": "You do not have permission"},
                     {"accessPolicies": [{"name": "x", "status": "ACTIVE"}], "accessRules": []},
                     {"accessPolicies": [], "accessRules": [], "signOnPolicies": [], "signOnRules": []}]:
            full = self.t.transform(body)
            self.assertIsNone(full["transformedResponse"][KEY], body)
            self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error", body)
            self.assertTrue(full["additionalInfo"]["dataCollection"]["errors"], body)

    def test_transformation_error_is_unevaluated(self):
        full = self.t.transform(b"not json")
        self.assertIsNone(full["transformedResponse"][KEY])
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error")

    def test_measured_verdicts_keep_data_collection_success(self):
        for body, expected in [(REAL, True)]:
            full = self.t.transform(body)
            self.assertIs(full["transformedResponse"][KEY], expected)
            self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][5][1] = catch_all()
        full = self.t.transform(flipped)
        self.assertIs(full["transformedResponse"][KEY], False)
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")

    def test_string_values_as_integration_service_returns_them(self):
        # Integration-Service stringifies scalars ("ACTIVE", "True", "2") in workflow output.
        data = copy.deepcopy(REAL)
        for rules in data["result"]["accessRules"]:
            for r in rules:
                r["system"] = str(r["system"])
                r["priority"] = str(r["priority"])
        data["result"]["accessRules"][5][0]["conditions"]["device"]["registered"] = "True"
        self.assertIs(self.out(data)[KEY], True)


if __name__ == "__main__":
    unittest.main()
