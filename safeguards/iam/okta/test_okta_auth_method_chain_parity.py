"""The AUTH_METHOD_CHAIN walker is copied into ismfaenforcedforusers.py, isstrongauthrequired.py and
isAdminMFAPhishingResistantPolicy.py (the sandbox forbids shared imports). This test keeps the three copies in line:
the same factor tables, and the same verdict on a shared table of chains (enough factor types, one factor type,
unreadable). Synthetic entries only."""
import copy
import importlib.util
import unittest
from pathlib import Path

from test_okta_auth_method_chain import body, chain, step, PASSWORD, QUESTION, FASTPASS

HERE = Path(__file__).parent
ROOT = HERE.resolve().parents[2]
TABLES = ["KNOWLEDGE_KEYS", "KNOWLEDGE_METHODS", "POSSESSION_KEYS", "POSSESSION_METHODS", "CHAIN_MAX_STEPS"]
MODULES = ["ismfaenforcedforusers", "isstrongauthrequired", "isAdminMFAPhishingResistantPolicy"]
KEYS = {"ismfaenforcedforusers": "isMFAEnforcedForUsers", "isstrongauthrequired": "isStrongAuthRequired",
        "isAdminMFAPhishingResistantPolicy": "isAdminMFAPhishingResistant"}
WEBAUTHN = {"key": "webauthn", "method": "webauthn", "userVerification": "OPTIONAL"}
WEBAUTHN_UV = {"key": "webauthn", "method": "webauthn", "userVerification": "REQUIRED"}
# (chain, expected verdict): True = two or more factor types, False = a way through proves one, None = unreadable
CASES = [
    (chain(step(PASSWORD, next=[step(WEBAUTHN)])), True),
    (chain(step(WEBAUTHN_UV)), True),
    (chain(step(PASSWORD, next=[step(WEBAUTHN), step(WEBAUTHN_UV)])), True),
    (chain(step(WEBAUTHN)), False),
    (chain(step(PASSWORD)), False),
    (chain(step(PASSWORD, next=[step(QUESTION)])), False),
    (chain(step(PASSWORD, WEBAUTHN, next=[step(WEBAUTHN)])), False),
    (chain(step({"key": "external_idp", "method": "idp"})), None),
    (chain(step(PASSWORD, next=[step({"key": "okta_verify_fastpass"})])), None),
    (chain(), None),
]


def module(name):
    spec = importlib.util.spec_from_file_location("parity_" + name, HERE / (name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def sandboxed(name):
    spec = importlib.util.spec_from_file_location("restricted_sandbox_parity", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / (name + ".py")).read_text(), "<transformation>")["transform"]


def request(name, method):
    data = body(method)
    if name == "isAdminMFAPhishingResistantPolicy":  # this one reads the Admin Console app's policy
        data["result"]["applications"] = [{"name": "saasure", "_links": {"accessPolicy": {
            "href": "https://example.okta.com/api/v1/policies/rst-1"}}}]
        data["result"]["accessRules"][0][0]["system"] = True
    return data


class ChainParityTests(unittest.TestCase):
    def test_factor_tables_are_identical(self):
        loaded = [module(name) for name in MODULES]
        for table in TABLES:
            self.assertEqual(len({repr(getattr(m, table)) for m in loaded}), 1, table)

    def test_same_verdict_on_the_shared_chains(self):
        for name in MODULES:
            for transform in [module(name).transform, sandboxed(name)]:
                for method, expected in CASES:
                    out = transform(copy.deepcopy(request(name, method)))["transformedResponse"][KEYS[name]]
                    self.assertIs(out, expected, (name, method))


if __name__ == "__main__":
    unittest.main()
