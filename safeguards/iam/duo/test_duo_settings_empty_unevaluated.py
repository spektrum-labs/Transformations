"""Duo getDuoSettings checks: a read that measured nothing is Unevaluated (all None, dataCollection error), never False.

authTypesAllowed and confirmPasswordPolicyEnforced used to answer False for {}, empty input, error bodies and
their except path. A real settings payload keeps its True/False answer exactly.
"""
import importlib.util
import json
import unittest
from pathlib import Path

CASES = {
    "authTypesAllowed": {
        "keys": ["authTypesAllowed", "enabledAuthTypes", "pushEnabled", "smsEnabled", "voiceEnabled",
                 "mobileOtpEnabled", "totalEnabledTypes"],
        "real": [
            ({"push_enabled": True, "sms_enabled": False, "voice_enabled": False, "mobile_otp_enabled": False}, True),
            ({"push_enabled": False, "sms_enabled": True, "voice_enabled": True, "mobile_otp_enabled": False}, False),
            ({"push_enabled": False, "sms_enabled": False, "voice_enabled": False, "mobile_otp_enabled": True}, True),
            ({"push_enabled": False}, False),
        ],
        "unmeasured": {"name": "Acme", "timezone": "UTC", "lockout_threshold": 10},
    },
    "confirmPasswordPolicyEnforced": {
        "keys": ["confirmPasswordPolicyEnforced", "minimumPasswordLength", "requiresUpperAlpha",
                 "requiresLowerAlpha", "requiresNumeric", "requiresSpecial", "lengthPolicyMet",
                 "complexityPolicyMet", "failingChecks"],
        "real": [
            ({"minimum_password_length": 12, "password_requires_upper_alpha": True,
              "password_requires_lower_alpha": True, "password_requires_numeric": True,
              "password_requires_special": True}, True),
            ({"minimum_password_length": 6, "password_requires_upper_alpha": True,
              "password_requires_lower_alpha": True, "password_requires_numeric": True,
              "password_requires_special": True}, False),
            ({"minimum_password_length": 12, "password_requires_upper_alpha": False,
              "password_requires_lower_alpha": True, "password_requires_numeric": True,
              "password_requires_special": True}, False),
            ({"minimum_password_length": 0}, False),
        ],
        "unmeasured": {"name": "Acme", "timezone": "UTC", "lockout_threshold": 10},
    },
}

BAD_INPUTS = [
    {}, "", b"", None, [], 42, "{bad json", b"\xff\xfe", "{}", "[]", "null",
    {"stat": "FAIL", "code": 40002, "message": "Invalid request parameters"},
    {"error": "boom"},
    {"statusCode": 500, "body": "oops"},
    {"response": {}}, {"response": "x"}, {"response": []},
    {"stat": "FAIL", "response": {"push_enabled": True}},
]


def load(key):
    spec = importlib.util.spec_from_file_location("duo_" + key, Path(__file__).with_name(key + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoSettingsEmptyUnevaluatedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = {k: load(k) for k in CASES}

    def assert_unevaluated(self, key, out):
        result = out["transformedResponse"]
        self.assertEqual(sorted(result), sorted(CASES[key]["keys"]))
        for k, v in result.items():
            self.assertIsNone(v, k)
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_real_settings_keep_their_answer(self):
        for key, case in CASES.items():
            for payload, expected in case["real"]:
                for wrapped in (payload, {"response": payload}, {"stat": "OK", "response": payload},
                                json.dumps(payload), {"data": payload, "validation": {"status": "success"}}):
                    with self.subTest(key=key, payload=str(wrapped)[:60]):
                        out = self.t[key].transform(wrapped)
                        self.assertIs(out["transformedResponse"][key], expected)
                        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_nothing_measured_is_unevaluated(self):
        for key, case in CASES.items():
            for payload in BAD_INPUTS + [case["unmeasured"], {"response": case["unmeasured"]},
                                         json.dumps(case["unmeasured"])]:
                with self.subTest(key=key, payload=str(payload)[:60]):
                    self.assert_unevaluated(key, self.t[key].transform(payload))

    def test_failed_validation_is_unevaluated(self):
        for key in CASES:
            with self.subTest(key=key):
                out = self.t[key].transform({"data": {"push_enabled": True}, "validation": {"status": "failed"}})
                self.assert_unevaluated(key, out)

    def test_exception_paths_are_unevaluated(self):
        for key in CASES:
            module = self.t[key]
            real = module.evaluate
            payload = CASES[key]["real"][0][0]

            def boom(data):
                raise RuntimeError("boom")

            try:
                module.evaluate = boom
                with self.subTest(key=key, path="outer except"):
                    self.assert_unevaluated(key, module.transform(payload))
            finally:
                module.evaluate = real
            with self.subTest(key=key, path="evaluate except"):
                # a value whose .get works but whose reads raise inside evaluate
                class Hostile(dict):
                    def get(self, *a, **k):
                        raise RuntimeError("hostile")
                self.assert_unevaluated(key, module.transform({"data": Hostile(payload), "validation": {"status": "ok"}}))

    def test_vendor_refusal_marker_still_first(self):
        marker = {"vendorErrorAsResponse": {"status": 403, "body": {"stat": "FAIL", "code": 40301,
                                                                   "message": "Access forbidden"}}}
        for key in CASES:
            with self.subTest(key=key):
                out = self.t[key].transform(marker)
                self.assert_unevaluated(key, out)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["errorCode"], "permission_not_granted")


if __name__ == "__main__":
    unittest.main()
