"""PingFederate isMFAEnforced called walk_node(), which was never defined.

Any enabled policy tree raised NameError, swallowed into a failed verdict. Behind it the file
returned its verdict under the wrong key and read a policy shape PingFederate does not send.
walk_node now exists and reads the real authnSelectionTrees shape, but the check answers None
(not evaluated): a policy names each authentication source by the administrator's instance id,
so an MFA adapter cannot be told from a password form without the adapter list. See the note in
ismfaenforced.py.

Every body below is synthetic and runs the file as production does, under the RestrictedPython
mirror in tools/restricted_sandbox.py, through walk_node.
"""
import importlib.util
import json
import pathlib
import unittest

HERE = pathlib.Path(__file__).parent
ROOT = HERE.resolve().parents[2]
KEY = "isMFAEnforced"


def _tool(name):
    spec = importlib.util.spec_from_file_location("pf_" + name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SANDBOX = _tool("restricted_sandbox")
NAMES = _tool("check_sandbox_names")


def run(body):
    return SANDBOX.load((HERE / "ismfaenforced.py").read_text(), "<transformation>")["transform"](body)


def source(instance_id, children=None):
    node = {"action": {"type": "AUTHN_SOURCE",
                       "authenticationSource": {"type": "IDP_ADAPTER", "sourceRef": {"id": instance_id}}}}
    if children:
        node["children"] = children
    return node


POLICY = {
    "failIfNoSelection": False,
    "authnSelectionTrees": [
        {"name": "Example primary", "enabled": True,
         "rootNode": source("ExampleForm", [
             {"action": {"type": "CONTINUE", "context": "Fail"}},
             source("ExampleSecondFactor", [{"action": {"type": "DONE", "context": "Success"}}]),
         ])},
        {"name": "Example disabled", "enabled": False, "rootNode": source("ExampleDisabled")},
    ],
}


class IsMFAEnforced(unittest.TestCase):
    def test_no_undefined_names(self):
        code = (HERE / "ismfaenforced.py").read_text()
        self.assertEqual(NAMES.undefined_names(code, NAMES.provided_names()), {})

    def test_walk_node_collects_sources_of_enabled_trees(self):
        out = run(POLICY)
        text = json.dumps(out)
        self.assertNotIn("is not defined", text, text)
        self.assertEqual(out["additionalInfo"]["transformation"]["status"], "success", text)
        tr = out["transformedResponse"]
        self.assertEqual(tr["authenticationSourcesReferenced"], ["ExampleForm", "ExampleSecondFactor"])
        self.assertEqual(tr["enabledPolicyTrees"], 1)

    def test_answers_not_evaluated_on_the_channel_the_evaluator_reads(self):
        for label, body in {"policy": POLICY, "empty": {}, "old invented shape":
                            {"authenticationPolicies": [{"authenticationPolicyTrees": [{"rootNode": source("X")}]}]}}.items():
            out = run(body)
            self.assertIsNone(out["transformedResponse"][KEY], label)
            self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error", label)
            self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"], label)


if __name__ == "__main__":
    unittest.main()
