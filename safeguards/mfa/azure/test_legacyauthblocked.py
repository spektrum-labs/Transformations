"""legacyAuthBlocked (legacyauthblocked.py) on GET /v1.0/identity/conditionalAccess/policies.

#101: the reasons name the accounts the legacy-auth block does not reach (named in a blocking policy but covered
by none: coverage is per principal, not the intersection of exclusions; or outside a block that does not target
all users), capped at 20 plus "and N more". The verdict is
unchanged. Fixtures are synthetic: zero-filled object ids, no customer data. Each case runs as plain Python and
in the Token-Service sandbox replica. The duplicate copy under safeguards/86ded564-.../ must stay byte-identical.
"""
import copy
import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("legacyauthblocked.py")
ROOT = PATH.resolve().parents[3]
DUPLICATE = ROOT / "safeguards" / "86ded564-522a-4c9b-9106-365e4cbdec7d" / "legacyauthblocked.py"
KEY = "legacyAuthBlocked"


def oid(n):
    return "00000000-0000-0000-0000-%012d" % n


def policy(state="enabled", clients=None, block=True, include_users=None, exclude_users=None,
           exclude_groups=None, exclude_roles=None, include_groups=None):
    return {
        "id": oid(9000),
        "displayName": "Block legacy authentication",
        "state": state,
        "conditions": {
            "clientAppTypes": ["exchangeActiveSync", "other"] if clients is None else clients,
            "users": {
                "includeUsers": ["All"] if include_users is None else include_users,
                "excludeUsers": exclude_users or [],
                "includeGroups": include_groups or [],
                "excludeGroups": exclude_groups or [],
                "includeRoles": [],
                "excludeRoles": exclude_roles or [],
            },
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"] if block else ["mfa"]},
    }


def body(*policies):
    return {"value": list(policies)}


def load():
    spec = importlib.util.spec_from_file_location("legacyauthblocked_entra", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    def __init__(self):
        spec = importlib.util.spec_from_file_location("restricted_sandbox_legacyauth", ROOT / "tools" / "restricted_sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


class LegacyAuthBlockedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, data):
        return self.t.transform(copy.deepcopy(data))

    def reasons(self, res, kind):
        return res["additionalInfo"]["evaluation"][kind]

    def test_duplicate_copy_is_identical(self):
        self.assertEqual(PATH.read_bytes(), DUPLICATE.read_bytes())

    def test_block_all_no_exclusions_passes_without_names(self):
        res = self.run_t(body(policy()))
        self.assertIs(res["transformedResponse"][KEY], True)
        self.assertEqual(res["transformedResponse"]["exemptPrincipals"], 0)
        first = self.reasons(res, "passReasons")[0]
        self.assertIn("1 enabled Conditional Access policy(ies) block legacy clients", first)
        self.assertNotIn("excluded", first)
        self.assertEqual(res["additionalInfo"]["evaluation"]["recommendations"], [])

    def test_exclusions_are_named_in_the_first_reason(self):
        res = self.run_t(body(policy(exclude_users=[oid(1)], exclude_groups=[oid(2)], exclude_roles=[oid(3)])))
        self.assertIs(res["transformedResponse"][KEY], True)
        first = self.reasons(res, "passReasons")[0]
        self.assertIn("3 account(s), group(s) or role(s) not covered by any", first)
        for ident in ["user:" + oid(1), "group:" + oid(2), "role:" + oid(3)]:
            self.assertIn(ident, first)
        self.assertEqual(res["transformedResponse"]["exemptPrincipals"], 3)
        self.assertNotIn("exemptPrincipalIds", res["transformedResponse"])
        self.assertEqual(len(res["additionalInfo"]["transformation"]["inputSummary"]["exemptPrincipalIds"]), 3)
        self.assertTrue(res["additionalInfo"]["evaluation"]["recommendations"])

    def test_names_capped_at_twenty_and_n_more(self):
        excluded = [oid(i) for i in range(100, 125)]
        res = self.run_t(body(policy(exclude_users=excluded)))
        first = self.reasons(res, "passReasons")[0]
        self.assertIn("25 account(s)", first)
        self.assertIn("and 5 more", first)
        self.assertEqual(first.count("user:"), 20)
        self.assertEqual(len(res["additionalInfo"]["transformation"]["inputSummary"]["exemptPrincipalIds"]), 20)

    def test_exactly_twenty_has_no_more_suffix(self):
        res = self.run_t(body(policy(exclude_users=[oid(i) for i in range(20)])))
        first = self.reasons(res, "passReasons")[0]
        self.assertEqual(first.count("user:"), 20)
        self.assertNotIn("more", first)

    def test_account_excluded_from_one_policy_but_caught_by_another_is_not_named(self):
        res = self.run_t(body(policy(exclude_users=[oid(1), oid(2)]), policy(exclude_users=[oid(2)])))
        first = self.reasons(res, "passReasons")[0]
        self.assertNotIn("user:" + oid(1), first)
        self.assertIn("user:" + oid(2), first)
        self.assertEqual(res["transformedResponse"]["exemptPrincipals"], 1)

    def test_excluded_from_all_users_block_and_outside_scoped_block_is_named(self):
        # Coverage per principal: user 1 is excluded from the All-users block and the other block is scoped to a
        # group, so nothing covers user 1, even though that second policy does not exclude it.
        res = self.run_t(body(policy(exclude_users=[oid(1)]), policy(include_users=[], include_groups=[oid(8)])))
        self.assertIs(res["transformedResponse"][KEY], True)
        first = self.reasons(res, "passReasons")[0]
        self.assertIn("user:" + oid(1), first)
        self.assertIn("not covered by any blocking policy", first)
        self.assertNotIn("group:" + oid(8), first.split("can still use them:")[1])
        self.assertEqual(res["transformedResponse"]["exemptPrincipals"], 1)

    def test_excluded_from_all_users_block_but_included_by_scoped_block_is_not_named(self):
        res = self.run_t(body(policy(exclude_users=[oid(1)]), policy(include_users=[oid(1)])))
        self.assertNotIn("user:" + oid(1), self.reasons(res, "passReasons")[0])
        self.assertEqual(res["transformedResponse"]["exemptPrincipals"], 0)

    def test_scoped_block_excluding_its_own_include_is_named(self):
        res = self.run_t(body(policy(include_users=[oid(7)], exclude_users=[oid(7)])))
        first = self.reasons(res, "passReasons")[0]
        self.assertIn("1 account(s)", first)
        self.assertIn("user:" + oid(7), first.split("can still use them:")[1])

    def test_scoped_block_names_its_scope(self):
        res = self.run_t(body(policy(include_users=[oid(7)], include_groups=[oid(8)])))
        self.assertIs(res["transformedResponse"][KEY], True)
        first = self.reasons(res, "passReasons")[0]
        self.assertIn("no blocking policy targets all users", first)
        self.assertIn("user:" + oid(7), first)
        self.assertIn("group:" + oid(8), first)

    def test_no_blocking_policy_fails_and_says_every_account(self):
        for p in [policy(state="disabled"), policy(state="enabledForReportingButNotEnforced"),
                  policy(block=False), policy(clients=["browser", "mobileAppsAndDesktopClients"])]:
            with self.subTest(p=p["state"]):
                res = self.run_t(body(p))
                self.assertIs(res["transformedResponse"][KEY], False)
                self.assertIn("every account in the tenant", self.reasons(res, "failReasons")[0])
                self.assertNotIn("exemptPrincipals", res["transformedResponse"])

    def test_disabled_policy_exclusions_do_not_leak_into_named_list(self):
        res = self.run_t(body(policy(), policy(state="disabled", exclude_users=[oid(5)])))
        self.assertNotIn(oid(5), self.reasons(res, "passReasons")[0])

    def test_error_input_keeps_the_original_failure_shape(self):
        res = self.run_t(["not", "a", "dict"])
        self.assertIs(res["transformedResponse"][KEY], False)
        self.assertEqual(self.reasons(res, "failReasons")[0], "legacyAuthBlocked check failed")

    def test_string_input_and_non_string_ids_are_tolerated(self):
        import json
        p = policy(exclude_users=[oid(1), None, 5, ""])
        res = self.run_t(json.dumps(body(p)))
        self.assertEqual(res["transformedResponse"]["exemptPrincipals"], 1)

    def test_overlong_identifier_is_truncated(self):
        res = self.run_t(body(policy(exclude_users=["x" * 500])))
        self.assertIn("user:" + "x" * 64, self.reasons(res, "passReasons")[0])
        self.assertNotIn("x" * 65, self.reasons(res, "passReasons")[0])


try:
    import RestrictedPython  # noqa: F401

    class LegacyAuthBlockedSandboxTests(LegacyAuthBlockedTests):
        @classmethod
        def setUpClass(cls):
            cls.t = SandboxModule()
except ImportError:  # CI installs RestrictedPython from requirements-test.txt
    pass


if __name__ == "__main__":
    unittest.main()
