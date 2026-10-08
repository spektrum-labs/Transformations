"""isRBACImplemented must not score a response it cannot read.

The Okta definition wires isRBACImplemented to getEstateSecondFactors (GET /api/v1/org/factors),
which returns a bare list of factor types. This generic file reads an object with an 'rbac' role
assignment list, so that list used to be scored False ("No RBAC role assignments found"), a
finding against the customer from a read that could not answer. It must be None (Not evaluated).

Fixtures are synthetic. FACTOR_CATALOGUE copies only the field names of that read
(factorType, provider, status), with made-up values.
"""
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isrbacimplemented.py")
KEY = "isRBACImplemented"
ROOT = PATH.resolve().parents[2]


def load():
    spec = importlib.util.spec_from_file_location("isrbacimplemented", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    """The same file compiled as Token-Service runs it (RestrictedPython replica in tools/)."""

    def __init__(self):
        spec = importlib.util.spec_from_file_location(
            "restricted_sandbox_isrbacimplemented", ROOT / "tools" / "restricted_sandbox.py"
        )
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


FACTOR_CATALOGUE = [
    {"factorType": "sms", "provider": "EXAMPLE", "status": "ACTIVE"},
    {"factorType": "token:software:totp", "provider": "EXAMPLE", "status": "ACTIVE"},
    {"factorType": "push", "provider": "EXAMPLE", "status": "NOT_SETUP"},
]
ROLES = [{"principal": "group-a", "role": "role-1"}, {"principal": "group-b", "role": "role-2"}]


class IsRbacImplementedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transforms = [load().transform, SandboxModule().transform]

    def each(self, payload):
        for transform in self.transforms:
            yield transform(payload)

    def assert_not_evaluated(self, out):
        self.assertIsNone(out["transformedResponse"][KEY])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertEqual(out["additionalInfo"]["evaluation"]["recommendations"], [])

    # --- wrong shape: Not evaluated -------------------------------------------------------

    def test_factor_catalogue_list_is_not_evaluated(self):
        for out in self.each(FACTOR_CATALOGUE):
            self.assert_not_evaluated(out)
            self.assertIn("list of 3 items", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_factor_catalogue_as_json_text_is_not_evaluated(self):
        for out in self.each(json.dumps(FACTOR_CATALOGUE)):
            self.assert_not_evaluated(out)

    def test_empty_list_is_not_evaluated(self):
        for out in self.each([]):
            self.assert_not_evaluated(out)

    def test_object_without_rbac_key_is_not_evaluated(self):
        for payload in ({}, {"roles": ROLES}, {"errorCode": "E0000006", "errorSummary": "denied"}):
            for out in self.each(payload):
                self.assert_not_evaluated(out)
                self.assertIn("without an 'rbac' key", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_non_object_json_is_not_evaluated(self):
        for payload in ("null", "true", "42", '"text"'):
            for out in self.each(payload):
                self.assert_not_evaluated(out)

    # --- shapes it reads today: unchanged -------------------------------------------------

    def test_rbac_list_passes(self):
        for out in self.each({"rbac": ROLES}):
            self.assertIs(out["transformedResponse"][KEY], True)
            self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
            self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"], {"rbacAssignments": 2})

    def test_empty_rbac_list_still_fails(self):
        for payload in ({"rbac": []}, {"rbac": None}, {"rbac": {}}):
            for out in self.each(payload):
                self.assertIs(out["transformedResponse"][KEY], False)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertEqual(out["additionalInfo"]["evaluation"]["failReasons"], ["No RBAC role assignments found"])

    def test_wrapped_and_text_inputs_still_read(self):
        wrapped = {"response": {"rbac": ROLES}}
        for out in self.each(wrapped):
            self.assertIs(out["transformedResponse"][KEY], True)
        for out in self.each(json.dumps({"rbac": ROLES})):
            self.assertIs(out["transformedResponse"][KEY], True)
        for out in self.each({"data": {"rbac": ROLES}, "validation": {"status": "ok", "errors": [], "warnings": []}}):
            self.assertIs(out["transformedResponse"][KEY], True)

    def test_failed_validation_still_false(self):
        envelope = {"data": {"rbac": ROLES}, "validation": {"status": "failed", "errors": ["bad"], "warnings": []}}
        for out in self.each(envelope):
            self.assertIs(out["transformedResponse"][KEY], False)


if __name__ == "__main__":
    unittest.main()
