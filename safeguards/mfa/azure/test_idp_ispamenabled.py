"""isPAMEnabled on identity-provider feeds (2026-10-03 false-fail check, PAM-2).

The three ispamenabled.py files are mapped to feeds that never carry privilegedAccounts or
pamPolicies: Graph GET /v1.0/users (Azure AD, Azure AD One-Click) and Okta
GET /api/v1/org/factors. An absent field is not evaluated, never a FAIL. There is no pass
path from PIM or LAPS data: those are not PAM evidence (J.J., 3 Oct 2026).
"""

import importlib.util
import unittest
from pathlib import Path


SAFEGUARDS = Path(__file__).resolve().parents[2]
PATHS = [
    SAFEGUARDS / "mfa" / "azure" / "ispamenabled.py",                                    # Azure AD
    SAFEGUARDS / "d9b6f27a-2e67-4b55-a09e-0784c5de9abd" / "ispamenabled.py",             # Azure AD One-Click
    SAFEGUARDS / "86ded564-522a-4c9b-9106-365e4cbdec7d" / "ispamenabled.py",             # Okta
]
KEY = "isPAMEnabled"


def load(path):
    spec = importlib.util.spec_from_file_location("ispam_" + path.parent.name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GRAPH_USERS = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
    "value": [{"id": "u1", "userPrincipalName": "admin@contoso.onmicrosoft.com", "mail": None}],
}
OKTA_FACTORS = [
    {"factorType": "push", "provider": "OKTA", "status": "ACTIVE"},
    {"factorType": "sms", "provider": "OKTA", "status": "INACTIVE"},
]
# PIM role-eligibility and LAPS-style data: not PAM evidence, so it must not pass.
PIM_AND_LAPS = {
    "value": [{"id": "e1", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "principalId": "u1",
               "memberType": "Direct", "status": "Provisioned"}],
    "deviceLocalCredentials": [{"deviceName": "PC-01", "lastBackupDateTime": "2026-10-01T00:00:00Z"}],
}


class PAMAbsentIsNotEvaluatedTests(unittest.TestCase):
    def run_all(self, body):
        for path in PATHS:
            out = load(path).transform(body)
            yield path, out["transformedResponse"][KEY], out["additionalInfo"]

    def test_absent_pam_fields_read_not_evaluated(self):
        for body in (GRAPH_USERS, OKTA_FACTORS, {}, [], {"value": []}, PIM_AND_LAPS,
                     {"apiResponse": GRAPH_USERS}):
            for path, verdict, info in self.run_all(body):
                with self.subTest(path=path.parent.name, body=str(body)[:40]):
                    self.assertFalse(verdict)
                    self.assertEqual(info["dataCollection"]["status"], "error")
                    self.assertTrue(info["dataCollection"]["errors"])
                    self.assertEqual(info["evaluation"]["failReasons"], [])

    def test_present_pam_data_still_discriminates(self):
        for path, verdict, info in self.run_all({"privilegedAccounts": [{"id": "vault-1"}]}):
            with self.subTest(path=path.parent.name):
                self.assertTrue(verdict)
                self.assertEqual(info["dataCollection"]["status"], "success")
        for path, verdict, info in self.run_all({"pamPolicies": []}):
            with self.subTest(path=path.parent.name):
                self.assertFalse(verdict)
                self.assertEqual(info["dataCollection"]["status"], "success")
                self.assertTrue(info["evaluation"]["failReasons"])


if __name__ == "__main__":
    unittest.main()
