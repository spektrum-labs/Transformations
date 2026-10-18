"""legacyAuthBlocked (legacyauthblocked.py): a policy list that was not read is Not evaluated, and Security Defaults
count as a block (Entra MFA review, 16 Oct 2026, defect 2).

Before this change an error envelope, a refused read, a missing or empty policy list, or a policy that is not an
object all read Failed ("value" defaulted to an empty list). A read that failed is not evidence either way, so each
now reads Not evaluated: value None and dataCollection.status "error".

Security Defaults (GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy, Policy.Read.All) block legacy
authentication for every account. When the merged input carries that body under "securityDefaults" and it reads
isEnabled true, the key passes. A Security Defaults read that is absent, refused or unreadable changes nothing: the
check behaves as it did before.

Fixtures are synthetic: zero-filled object ids, no customer data. Every case also runs in the Token-Service sandbox
replica. The duplicate copy under safeguards/86ded564-.../ must stay byte-identical.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("legacyauthblocked.py")
ROOT = PATH.resolve().parents[3]
KEY = "legacyAuthBlocked"


def oid(n):
    return "00000000-0000-0000-0000-%012d" % n


def policy(state="enabled", clients=None, block=True):
    return {
        "id": oid(9000),
        "displayName": "Block legacy authentication",
        "state": state,
        "conditions": {
            "clientAppTypes": ["exchangeActiveSync", "other"] if clients is None else clients,
            "users": {"includeUsers": ["All"], "excludeUsers": [], "includeGroups": [], "excludeGroups": [],
                      "includeRoles": [], "excludeRoles": []},
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"] if block else ["mfa"]},
    }


def body(*policies):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
            "value": list(policies)}


def defaults(enabled):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/identitySecurityDefaultsEnforcementPolicy/$entity",
            "id": "00000000-0000-0000-0000-000000000005", "displayName": "Security Defaults", "isEnabled": enabled}


def with_defaults(ca_body, sd_body):
    """The shape the Azure MFA workflow sends: the policy list merged at the top, Security Defaults under its key."""
    merged = dict(ca_body)
    merged["securityDefaults"] = sd_body
    return merged


GRAPH_ERROR = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
REFUSED = {"vendorErrorAsResponse": {"status": "403", "kind": "missing_permission"}}
STEP_ERROR = {"stepError": True, "statusCode": 403, "errorSummary": "Forbidden"}
NO_LICENCE = {"error": {"code": "BadRequest", "message": "Tenant is not licensed for this feature"}}


def load():
    spec = importlib.util.spec_from_file_location("legacyauthblocked_row36", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    def __init__(self):
        spec = importlib.util.spec_from_file_location("restricted_sandbox_row36", ROOT / "tools" / "restricted_sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


class LegacyAuthNotEvaluatedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, data):
        return self.t.transform(copy.deepcopy(data))

    def assert_not_evaluated(self, res, fragment=None):
        self.assertIsNone(res["transformedResponse"][KEY])
        collection = res["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertEqual(res["additionalInfo"]["evaluation"]["failReasons"], [])
        if fragment:
            self.assertIn(fragment, " ".join(collection["errors"]))

    # --- defect 2a: an unread, refused or empty list is Not evaluated, never Failed ---

    def test_graph_error_envelope_is_not_evaluated(self):
        for err in (GRAPH_ERROR, NO_LICENCE):
            with self.subTest(err=err["error"]["code"]):
                self.assert_not_evaluated(self.run_t(err), "not read")

    def test_refused_read_is_not_evaluated(self):
        self.assert_not_evaluated(self.run_t(REFUSED), "not read")

    def test_step_error_marker_is_not_evaluated(self):
        self.assert_not_evaluated(self.run_t(STEP_ERROR), "not read")

    def test_empty_policy_list_is_not_evaluated(self):
        self.assert_not_evaluated(self.run_t(body()), "no Conditional Access policies")

    def test_missing_or_malformed_value_is_not_evaluated(self):
        for data in ({}, {"@odata.context": "x"}, {"value": None}, {"value": "policies"}, {"value": {"a": 1}}):
            with self.subTest(data=data):
                self.assert_not_evaluated(self.run_t(data))

    def test_policy_that_is_not_an_object_is_not_evaluated(self):
        self.assert_not_evaluated(self.run_t(body(policy(block=False), "not-a-policy")))

    def test_non_dict_input_is_not_evaluated(self):
        for data in (["not", "a", "dict"], None, 7, "null"):
            with self.subTest(data=data):
                self.assert_not_evaluated(self.run_t(data))

    def test_partial_list_without_a_block_is_not_evaluated(self):
        paged = body(policy(block=False))
        paged["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=x"
        self.assert_not_evaluated(self.run_t(paged), "partial")
        truncated = body(policy(block=False))
        truncated["paginationTruncated"] = True
        self.assert_not_evaluated(self.run_t(truncated), "partial")

    def test_partial_list_with_a_block_still_passes(self):
        paged = body(policy())
        paged["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=x"
        self.assertIs(self.run_t(paged)["transformedResponse"][KEY], True)

    def test_validation_failure_is_not_evaluated(self):
        res = self.run_t({"data": body(policy()), "validation": {"status": "failed", "errors": ["bad"], "warnings": []}})
        self.assert_not_evaluated(res)

    # --- defect 2b: Security Defaults enabled reads legacy auth as blocked ---

    def test_security_defaults_enabled_with_empty_list_passes(self):
        res = self.run_t(with_defaults(body(), defaults(True)))
        self.assertIs(res["transformedResponse"][KEY], True)
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertIn("Security Defaults", res["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_security_defaults_enabled_passes_even_when_the_policy_list_was_not_read(self):
        for ca in (GRAPH_ERROR, REFUSED):
            with self.subTest(ca=list(ca)[0]):
                merged = dict(ca)
                merged["securityDefaults"] = defaults(True)
                self.assertIs(self.run_t(merged)["transformedResponse"][KEY], True)

    def test_security_defaults_enabled_as_text_passes(self):
        self.assertIs(self.run_t(with_defaults(body(), defaults("true")))["transformedResponse"][KEY], True)

    def test_security_defaults_in_the_keyed_shape_passes(self):
        res = self.run_t({"conditionalAccessPolicies": body(), "securityDefaults": defaults(True)})
        self.assertIs(res["transformedResponse"][KEY], True)

    def test_security_defaults_disabled_changes_nothing(self):
        self.assertIs(self.run_t(with_defaults(body(policy(block=False)), defaults(False)))
                      ["transformedResponse"][KEY], False)
        self.assertIs(self.run_t(with_defaults(body(policy()), defaults(False)))["transformedResponse"][KEY], True)
        self.assert_not_evaluated(self.run_t(with_defaults(body(), defaults(False))))

    def test_security_defaults_unreadable_behaves_as_without_it(self):
        for sd in (STEP_ERROR, GRAPH_ERROR, REFUSED, {"isEnabled": None}, {"isEnabled": "maybe"}, "x", None,
                   {"isEnabled": True, "error": {"code": "x"}}):
            with self.subTest(sd=sd):
                failed = self.run_t(with_defaults(body(policy(block=False)), sd))
                self.assertIs(failed["transformedResponse"][KEY], False)
                self.assertEqual(failed["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertIs(self.run_t(with_defaults(body(policy()), sd))["transformedResponse"][KEY], True)
                self.assert_not_evaluated(self.run_t(with_defaults(body(), sd)))

    # --- what did not change ---

    def test_read_list_with_no_blocking_policy_still_fails(self):
        res = self.run_t(body(policy(block=False), policy(state="disabled")))
        self.assertIs(res["transformedResponse"][KEY], False)
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertIn("every account in the tenant", res["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_blocking_policy_still_passes_with_the_same_output(self):
        res = self.run_t(body(policy()))
        self.assertIs(res["transformedResponse"][KEY], True)
        self.assertEqual(res["transformedResponse"]["blockingPolicies"], 1)
        self.assertEqual(res["transformedResponse"]["exemptPrincipals"], 0)

    def test_json_string_input(self):
        self.assertIs(self.run_t(json.dumps(with_defaults(body(), defaults(True))))["transformedResponse"][KEY], True)


try:
    import RestrictedPython  # noqa: F401

    class LegacyAuthNotEvaluatedSandboxTests(LegacyAuthNotEvaluatedTests):
        @classmethod
        def setUpClass(cls):
            cls.t = SandboxModule()
except ImportError:  # CI installs RestrictedPython from requirements-test.txt
    pass


if __name__ == "__main__":
    unittest.main()
