"""PingFederate authTypesAllowed and isMFAEnabled answered False for every tenant.

Both files classified adapters with `plugin_id in <NAME>` where <NAME> -- STRONG_MFA_PLUGINS /
WEAK_MFA_PLUGINS in one, MFA_ADAPTER_PLUGINS in the other -- was never defined anywhere in the
file. The only imports are json and datetime. A bare `except Exception` in evaluate() swallowed
the NameError into {"<key>": False, "error": "name '...' is not defined"}, so the result was a
silent always-False with the Python error text leaking into the customer-visible failReasons.

Measured before the fix, against a realistic /pf-admin-api/v1/idp/adapters body:

    failReasons = ['authTypesAllowed check failed', "name 'STRONG_MFA_PLUGINS' is not defined"]

The list could not simply be filled in. Researched 2026-10-05: no verified pluginDescriptorRef.id
exists for ANY phishing-resistant PingFederate adapter -- not FIDO2/WebAuthn, not X.509, not
Composite -- so a strong-factor allowlist cannot be populated and the check could not reach True.
Separately, /idp/adapters lists adapters that are CONFIGURED, not ones a policy requires, so it is
the wrong evidence for the claim even with a correct list.

Both now answer None (not evaluated) with a reason that names both limitations.
"""
import importlib.util
import pathlib
import re
import unittest

HERE = pathlib.Path(__file__).parent
ROOT = HERE.resolve().parents[2]

CASES = (("authtypesallowed.py", "authTypesAllowed"),
         ("ismfaenabled.py", "isMFAEnabled"))


def load(filename):
    path = HERE / filename
    spec = importlib.util.spec_from_file_location(filename.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sandbox(filename):
    """The same file compiled as Token-Service runs it (RestrictedPython replica in tools/)."""
    path = HERE / filename
    spec = importlib.util.spec_from_file_location("rs_" + filename, ROOT / "tools" / "restricted_sandbox.py")
    sb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sb)
    return sb.load(path.read_text(), "<transformation>")["transform"]


def adapter(plugin_id, adapter_id="A"):
    return {"id": adapter_id, "pluginDescriptorRef": {"id": plugin_id}}


REAL = {"items": [
    adapter("com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter", "HTMLForm"),
    adapter("com.pingidentity.adapters.pingid.PingIDAdapter", "PingID"),
]}

BODIES = {"realistic": REAL, "empty dict": {}, "no items": {"items": []},
          "error body": {"error": "boom"}, "items not a list": {"items": "nope"}}


def verdict(response, key):
    return response["transformedResponse"][key]


def reasons(response):
    ev = response["additionalInfo"]["evaluation"]
    return " ".join(ev["passReasons"] + ev["failReasons"])


class NeitherCheckAnswersFromAnUnusableList(unittest.TestCase):
    def test_no_body_produces_a_verdict(self):
        for filename, key in CASES:
            transform = load(filename).transform
            for label, body in BODIES.items():
                self.assertIsNone(verdict(transform(body), key), f"{filename} / {label}")

    def test_nothing_can_return_true(self):
        """A strong-factor allowlist cannot be populated, so a pass would be unearned."""
        for filename, key in CASES:
            transform = load(filename).transform
            for body in BODIES.values():
                self.assertIsNot(verdict(transform(body), key), True)

    def test_nothing_returns_false_either(self):
        """False is a finding against the customer, and we have not established one."""
        for filename, key in CASES:
            transform = load(filename).transform
            for body in BODIES.values():
                self.assertIsNot(verdict(transform(body), key), False)


class TheCustomerIsToldSomethingTrue(unittest.TestCase):
    def test_no_python_error_text_reaches_the_customer(self):
        for filename, _ in CASES:
            transform = load(filename).transform
            for label, body in BODIES.items():
                text = reasons(transform(body))
                self.assertNotIn("is not defined", text, f"{filename} / {label}")
                self.assertNotIn("Traceback", text)

    def test_the_reason_names_both_limitations(self):
        for filename, _ in CASES:
            text = reasons(load(filename).transform(REAL))
            self.assertIn("/pf-admin-api/v1/idp/adapters", text)
            self.assertIn("not which an authentication policy requires", text)
            self.assertIn("not evaluated", text)

    def test_it_does_not_recommend_remediation_for_a_finding_it_did_not_make(self):
        for filename, _ in CASES:
            response = load(filename).transform(REAL)
            self.assertEqual(response["additionalInfo"]["evaluation"]["recommendations"], [])


class TheUndefinedNamesAreGone(unittest.TestCase):
    def test_no_file_references_a_name_it_never_defines(self):
        for filename, _ in CASES:
            source = (HERE / filename).read_text()
            for name in ("STRONG_MFA_PLUGINS", "WEAK_MFA_PLUGINS", "MFA_ADAPTER_PLUGINS"):
                used = re.search(r"^(?!\s*#).*\b%s\b" % name, source, re.M)
                self.assertIsNone(used, f"{filename} still uses {name} in code")

    def test_the_fabricated_identifier_is_not_adopted(self):
        """integration_configs/docs/ping_federate/ stages a plausible but wrong list.

        It names com.pingidentity.adapters.pingid.idp.PingIDAuthnAdapter where the real adapter is
        com.pingidentity.adapters.pingid.PingIDAdapter, and its FIDO2/TOTP/HOTP/OATH ids appear
        nowhere outside Spektrum's own repositories. Adopting it would hide this bug, not fix it.
        """
        for filename, _ in CASES:
            source = (HERE / filename).read_text()
            code = "\n".join(l for l in source.splitlines() if not l.lstrip().startswith("#"))
            self.assertNotIn("Fido2IdpAuthnAdapter", code)
            self.assertNotIn("PingIDAuthnAdapter", code)
            self.assertNotIn("TotpIdpAuthnAdapter", code)


class RunsUnderTheSandbox(unittest.TestCase):
    def test_both_compile_and_answer_none(self):
        for filename, key in CASES:
            transform = sandbox(filename)
            self.assertIsNone(verdict(transform(REAL), key), filename)
            self.assertIsNone(verdict(transform({}), key), filename)


if __name__ == "__main__":
    unittest.main()
