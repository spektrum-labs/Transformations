"""AUTH_METHOD_CHAIN rules in Okta authentication policies, read by isMFAEnforcedForUsers (and isMFAEnabled) and
isStrongAuthRequired.

Synthetic fixtures in the shape of the Okta Policy API (verificationMethod.type AUTH_METHOD_CHAIN, chains[] of
{authenticationMethods[], next[], reauthenticateIn}). Both transforms are also run through the RestrictedPython
replica in tools/, the way Token-Service runs them.
"""
import copy
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location("okta_chain_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(name):
    spec = importlib.util.spec_from_file_location("restricted_sandbox_okta_chain", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / (name + ".py")).read_text(), "<transformation>")["transform"]


PASSWORD = {"key": "okta_password", "method": "password"}
PUSH = {"key": "okta_verify", "method": "push"}
FASTPASS = {"key": "okta_verify", "method": "signed_nonce", "userVerification": "REQUIRED"}
FASTPASS_NO_UV = {"key": "okta_verify", "method": "signed_nonce", "userVerification": "OPTIONAL"}
SMS = {"key": "phone_number", "method": "sms"}
EMAIL = {"key": "okta_email", "method": "email"}
QUESTION = {"key": "security_question", "method": "security_question"}


def step(*methods, **kw):
    node = {"authenticationMethods": list(methods), "reauthenticateIn": "PT12H"}
    if kw.get("next") is not None:
        node["next"] = kw["next"]
    return node


def chain(*chains):
    return {"type": "AUTH_METHOD_CHAIN", "chains": list(chains), "reauthenticateIn": "PT12H"}


def body(method):
    """An Identity Engine read with one app policy whose only allowing rule uses method."""
    return {"result": {
        "signOnPolicies": [{"id": "pol-d", "name": "Default Policy", "status": "ACTIVE", "system": True}],
        "signOnRules": [[{"id": "rul-d", "name": "Default Rule", "status": "ACTIVE", "system": True,
                          "actions": {"signon": {"access": "ALLOW", "primaryFactor": "PASSWORD_IDP_ANY_FACTOR"}}}]],
        "accessPolicies": [{"id": "rst-1", "name": "Example app policy", "status": "ACTIVE",
                            "_embedded": {"resourceType": "APP"}}],
        "accessRules": [[{"id": "rul-1", "name": "Chained", "status": "ACTIVE",
                          "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": method}}}]],
        "authenticators": [{"key": "okta_password", "status": "ACTIVE"}, {"key": "okta_verify", "status": "ACTIVE"}],
    }}


REAL = chain(step(PASSWORD, next=[step(PUSH, FASTPASS)]))


class ChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runs = []
        for name in ["ismfaenforcedforusers", "isstrongauthrequired"]:
            cls.runs.append((name, load(name)))
            cls.runs.append((name + " (sandbox)", sandboxed(name)))

    def values(self, method):
        out = {}
        for label, transform in self.runs:
            result = transform(copy.deepcopy(body(method)))
            response = result["transformedResponse"]
            status = result["additionalInfo"]["dataCollection"]["status"]
            if label.startswith("ismfaenforcedforusers"):
                out[label] = (response["isMFAEnforcedForUsers"], response["isMFAEnabled"], status)
            else:
                out[label] = (response["isStrongAuthRequired"], status)
        return out

    def assert_values(self, method, mfa, enabled, strong):
        for label, value in self.values(method).items():
            if label.startswith("ismfaenforcedforusers"):
                expected = (mfa, enabled, "error" if mfa is None else "success")
            else:
                expected = (strong, "error" if strong is None else "success")
            self.assertEqual(value, expected, label)

    def test_real_shape_password_then_okta_verify_is_two_factor_and_strong(self):
        self.assert_values(REAL, True, True, True)

    def test_fastpass_with_user_verification_alone_is_two_factor(self):
        self.assert_values(chain(step(FASTPASS)), True, True, True)

    def test_flipped_password_alone_is_a_single_factor_path(self):
        self.assert_values(chain(step(PASSWORD)), False, False, False)

    def test_fastpass_without_user_verification_alone_is_one_factor(self):
        self.assert_values(chain(step(FASTPASS_NO_UV)), False, False, False)

    def test_any_single_factor_way_through_the_chain_fails(self):
        # Password may be skipped in favour of push, then push again: one factor type.
        self.assert_values(chain(step(PASSWORD, PUSH, next=[step(PUSH)])), False, False, False)
        # A second, shorter chain beside a two-step one.
        self.assert_values(chain(step(PASSWORD, next=[step(PUSH)]), step(PUSH)), False, False, False)
        # Two knowledge factors are one type.
        self.assert_values(chain(step(PASSWORD, next=[step(QUESTION)])), False, False, False)

    def test_weak_second_factor_is_mfa_but_not_strong(self):
        self.assert_values(chain(step(PASSWORD, next=[step(SMS)])), True, True, False)
        self.assert_values(chain(step(PASSWORD, next=[step(PUSH, EMAIL)])), True, True, False)

    def test_branching_next_steps_are_each_judged(self):
        self.assert_values(chain(step(PASSWORD, next=[step(PUSH), step(FASTPASS)])), True, True, True)
        self.assert_values(chain(step(PASSWORD, next=[step(PUSH), step(SMS)])), True, True, False)

    def test_unknown_authenticator_or_shape_is_not_evaluated(self):
        for method in [
            chain(step({"key": "external_idp", "method": "idp"})),
            chain(step(PASSWORD, next=[step({"id": "aut-1"})])),
            chain(step(PASSWORD, next={"authenticationMethods": [PUSH]})),
            chain(step()),
            chain(),
            {"type": "AUTH_METHOD_CHAIN"},
            {"type": "AUTH_METHOD_CHAIN", "chains": None},
            {"type": "AUTH_METHOD_CHAIN", "chains": ["not an object"]},
            {"type": "AUTH_METHOD_CHAIN", "chains": [{"authenticationMethods": None}]},
            {"type": "AUTH_METHOD_CHAIN", "chains": {"errorCode": "E0000001"}},
        ]:
            self.assert_values(method, None, None, None)

    def test_too_deep_chain_is_not_evaluated(self):
        node = step(PUSH)
        for i in range(6):
            node = step(PASSWORD if i % 2 else PUSH, next=[node])
        self.assert_values(chain(node), None, None, None)

    def test_readable_weak_rule_beside_an_unreadable_chain_still_fails(self):
        for label, transform in self.runs:
            data = body(chain(step({"key": "external_idp"})))
            data["result"]["accessRules"][0].append(
                {"id": "rul-2", "name": "Password only", "status": "ACTIVE",
                 "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": chain(step(PASSWORD))}}})
            response = transform(data)["transformedResponse"]
            if label.startswith("ismfaenforcedforusers"):
                self.assertIsNone(response["isMFAEnforcedForUsers"], label)  # one key None withholds both
            else:
                self.assertIs(response["isStrongAuthRequired"], False, label)


if __name__ == "__main__":
    unittest.main()
