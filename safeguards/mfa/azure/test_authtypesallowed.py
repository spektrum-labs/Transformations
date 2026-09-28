import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("authtypesallowed.py")


def load_transformation():
    spec = importlib.util.spec_from_file_location("azure_authtypesallowed", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(enabled):
    """Graph GET /v1.0/policies/authenticationMethodsPolicy: a single object, not a list."""
    ids = ["Email", "Fido2", "MicrosoftAuthenticator", "QRCodePin", "Sms", "SoftwareOath",
           "TemporaryAccessPass", "VerifiableCredentials", "Voice", "X509Certificate"]
    return {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/$entity",
        "id": "authenticationMethodsPolicy",
        "authenticationMethodConfigurations": [
            {"id": i, "state": "enabled" if i in enabled else "disabled"} for i in ids
        ],
    }


class AzureAuthTypesAllowedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def verdict(self, body):
        out = self.t.transform(body)
        return out["transformedResponse"]["authTypesAllowed"], out["additionalInfo"]["dataCollection"]["status"]

    def test_policy_object_with_weak_method_is_evaluated_false(self):
        self.assertEqual(self.verdict(policy({"Fido2", "MicrosoftAuthenticator", "Email"})), (False, "success"))

    def test_policy_object_with_only_strong_methods_is_evaluated_true(self):
        self.assertEqual(self.verdict(policy({"Fido2", "MicrosoftAuthenticator", "SoftwareOath"})), (True, "success"))

    def test_no_evidence_fails_closed(self):
        for body in ({}, [], None,
                     {"error": {"code": "InvalidAuthenticationToken"}, "status_code": 401},
                     {"error": {"code": "Authorization_RequestDenied"}, "status_code": 403}):
            with self.subTest(body=body):
                self.assertEqual(self.verdict(body), (False, "error"))


if __name__ == "__main__":
    unittest.main()
