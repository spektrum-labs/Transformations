"""A None verdict must carry dataCollection.status "error".

Token-Service grades a transform result of None as Failed unless
additionalInfo.dataCollection.status is "error" (that needs api_errors). These
two Okta transforms return None when the response cannot answer the check
(islifecyclemanagementenabled already passed api_errors; it is pinned here as a regression).
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FACTOR_CATALOGUE = [
    {"factorType": "sms", "provider": "OKTA", "status": "ACTIVE"},
    {"factorType": "token:software:totp", "provider": "OKTA", "status": "ACTIVE"},
    {"factorType": "push", "provider": "OKTA", "status": "NOT_SETUP"},
]


class NoneReadsAsNotEvaluated(unittest.TestCase):
    def assert_not_evaluated(self, out, key):
        self.assertIsNone(out["transformedResponse"][key])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])

    def test_strong_auth_on_factor_catalogue(self):
        out = load("isstrongauthrequired").transform(FACTOR_CATALOGUE)
        self.assert_not_evaluated(out, "isStrongAuthRequired")

    def test_strong_auth_on_unreadable_body(self):
        out = load("isstrongauthrequired").transform({"errorCode": "E0000006", "errorSummary": "denied"})
        self.assert_not_evaluated(out, "isStrongAuthRequired")

    def test_strong_auth_policy_list_still_measured(self):
        out = load("isstrongauthrequired").transform([{"id": "p1", "status": "ACTIVE", "type": "ACCESS_POLICY"}])
        self.assertIs(out["transformedResponse"]["isStrongAuthRequired"], True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_lifecycle_on_factor_list(self):
        out = load("islifecyclemanagementenabled").transform(FACTOR_CATALOGUE)
        self.assert_not_evaluated(out, "isLifeCycleManagementEnabled")


if __name__ == "__main__":
    unittest.main()
