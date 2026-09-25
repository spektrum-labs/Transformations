"""The requirement asks isEquals FALSE, so False is the compliant answer.

Only a read-and-false settings row may return False. Anything unknown must return
None, which never equals false, so it cannot satisfy the requirement.
"""
import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("iscodeexecutionnetworkegressenabled.py")
KEY = "isCodeExecutionNetworkEgressEnabled"


def load():
    spec = importlib.util.spec_from_file_location("iscodeexecutionnetworkegressenabled", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rows(**kv):
    return [{"name": k, "value": v} for k, v in kv.items()]


# Shape Integration-Service relayed for this definition on 2026-09-25 (vendor 401).
RELAY_401 = {"result": {"integrationName": "Anthropic-Artificial Intelligence",
                        "errorMessage": "x-api-key header is required", "vendorStatus": 401}}


class CodeExecutionEgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def value(self, payload):
        return self.t.transform(payload)["transformedResponse"][KEY]

    def test_read_false_is_the_only_compliant_answer(self):
        self.assertIs(self.value(rows(code_execution_network_egress_enabled=False)), False)

    def test_read_true_fails(self):
        self.assertIs(self.value(rows(code_execution_network_egress_enabled=True)), True)

    def test_missing_row_is_not_controllable_not_off(self):
        self.assertIsNone(self.value(rows(code_execution_enabled=True)))

    def test_null_value_is_unknown(self):
        self.assertIsNone(self.value(rows(code_execution_network_egress_enabled=None)))

    def test_refused_call_is_unknown_and_not_evaluated(self):
        out = self.t.transform(RELAY_401)
        self.assertIsNone(out["transformedResponse"][KEY])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_empty_and_error_inputs_are_unknown(self):
        for payload in ([], {}, None, "{}", "<html>502</html>"):
            self.assertIsNone(self.value(payload), repr(payload))


if __name__ == "__main__":
    unittest.main()
