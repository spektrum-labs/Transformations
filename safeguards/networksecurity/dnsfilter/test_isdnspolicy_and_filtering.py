"""isDNSPolicyConfigured and isDNSFilteringEnabled must read DNSFilter's real JSON:API bodies.

isDNSPolicyConfigured read `blocked_categories` at the top level of each policy, a field
GET /v1/policies never returns (the API puts `blacklist_categories` under `attributes`), and then
passed any organisation that had a policy at all. isDNSFilteringEnabled counted a network with no
status field as active (DNSFilter networks have none), counted deleted networks, and passed even
when it judged every network inactive. All fixtures below are synthetic.
"""
import importlib.util
import json
import types
import unittest
from pathlib import Path

try:
    import RestrictedPython  # noqa: F401  the production sandbox replica needs it
    HAVE_SANDBOX = True
except ImportError:
    HAVE_SANDBOX = False

HERE = Path(__file__).resolve().parent


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(pid, categories, allow_list_only=False, deleted_at=None, name="Example Policy"):
    """One policy as GET /v1/policies returns it (synthetic values)."""
    return {"id": str(pid), "type": "policies",
            "attributes": {"name": name, "organization_id": 4242, "blacklist_categories": categories,
                           "block_applications": [], "allow_list_only": allow_list_only,
                           "whitelist_domains": [], "blacklist_domains": [], "deleted_at": deleted_at,
                           "is_global_policy": False}}


def network(nid, ip_count=0, deleted_at=None, policy_id=1001):
    """One network as GET /v1/networks returns it (synthetic values): no status field."""
    return {"id": str(nid), "type": "networks",
            "attributes": {"name": "Example Site", "policy_id": policy_id, "deleted_at": deleted_at,
                           "ip_count": ip_count, "truncated_ip_count": 0},
            "relationships": {"organization": {"data": {"id": "4242", "type": "organizations"}}}}


def raw(*items):
    """The raw vendor body; Token-Service strips `data`, so most tests pass the bare list instead."""
    return {"data": list(items), "links": {"self": "https://api.example.invalid/v1/x"}, "meta": {}}


def enriched(data, status="passed"):
    return {"data": data, "validation": {"status": status, "errors": [], "warnings": []}}


class NotMeasured:
    KEY = None

    def verdict(self, out):
        return out["transformedResponse"][self.KEY]

    def not_measured(self, out, raised=False):
        self.assertIsNone(self.verdict(out))
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])
        if not raised:
            self.assertEqual(out["additionalInfo"]["transformation"]["errors"], [])

    def measured(self, out):
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")


class IsDnsPolicyConfiguredTests(NotMeasured, unittest.TestCase):
    KEY = "isDNSPolicyConfigured"

    @classmethod
    def setUpClass(cls):
        cls.t = load(HERE / "isdnspolicyconfigured.py", "dnsfilter_isdnspolicyconfigured")

    def test_a_policy_blocking_categories_passes(self):
        out = self.t.transform([policy(1, [1, 2, 3, 4], name="Strict")])
        self.measured(out)
        self.assertIs(self.verdict(out), True)
        self.assertEqual(out["transformedResponse"]["policiesWithBlocks"], 1)
        self.assertEqual(out["transformedResponse"]["totalBlockedCategories"], 4)
        self.assertIn("Strict", out["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_the_raw_body_enriched_body_and_string_read_the_same(self):
        for body in (raw(policy(1, [7, 8])), enriched([policy(1, [7, 8])]),
                     json.dumps([policy(1, [7, 8])]), {"response": raw(policy(1, [7, 8]))}):
            with self.subTest(body=str(body)[:40]):
                out = self.t.transform(body)
                self.assertIs(self.verdict(out), True)
                self.assertEqual(out["transformedResponse"]["totalBlockedCategories"], 2)

    def test_an_allow_list_only_policy_passes(self):
        out = self.t.transform([policy(1, [], allow_list_only=True)])
        self.assertIs(self.verdict(out), True)

    def test_policies_that_block_no_category_fail(self):
        """The old transform passed here: a policy existed, so it was 'configured'."""
        out = self.t.transform([policy(1, []), policy(2, [])])
        self.measured(out)
        self.assertIs(self.verdict(out), False)
        self.assertEqual(out["transformedResponse"]["totalPolicies"], 2)
        self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])

    def test_the_old_top_level_field_is_not_believed(self):
        """`blocked_categories` beside `attributes` is not an API field; only attributes count."""
        body = policy(1, [])
        body["blocked_categories"] = [1, 2, 3]
        self.assertIs(self.verdict(self.t.transform([body])), False)

    def test_a_deleted_policy_does_not_count(self):
        out = self.t.transform([policy(1, [1, 2], deleted_at="2026-01-01T00:00:00Z"), policy(2, [])])
        self.assertIs(self.verdict(out), False)
        self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"]["deletedPolicies"], 1)

    def test_only_deleted_policies_is_not_measured(self):
        out = self.t.transform([policy(1, [1], deleted_at="2026-01-01T00:00:00Z")])
        self.not_measured(out)
        self.assertIn("deleted", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_one_filtering_policy_among_open_ones_passes(self):
        out = self.t.transform([policy(1, []), policy(2, [5])])
        self.assertIs(self.verdict(out), True)
        self.assertEqual(out["transformedResponse"]["policiesWithBlocks"], 1)

    def test_an_unreadable_policy_blocks_a_false(self):
        """A False needs every live policy read: the unreadable one might be the one that filters."""
        bad = policy(2, [])
        del bad["attributes"]["blacklist_categories"]
        self.not_measured(self.t.transform([policy(1, []), bad]))
        self.not_measured(self.t.transform([policy(1, []), "garbage"]))

    def test_an_unreadable_policy_beside_a_filtering_one_still_passes_and_says_so(self):
        bad = policy(2, [])
        bad["attributes"]["blacklist_categories"] = "many"
        out = self.t.transform([policy(1, [3]), bad])
        self.assertIs(self.verdict(out), True)
        self.assertEqual(len(out["additionalInfo"]["evaluation"]["additionalFindings"]), 1)

    def test_an_empty_list_is_not_measured(self):
        """Every DNSFilter network points at a policy, so no policies means the read did not see them."""
        for body in ([], raw(), enriched([])):
            with self.subTest(body=body):
                self.not_measured(self.t.transform(body))

    def test_bodies_that_prove_nothing_are_not_measured(self):
        for body in ({}, "{}", None, {"error": "Not Authorized"}, {"errors": [{"detail": "Not found"}]},
                     {"hello": "world"}, {"data": {"id": 1}}, 7):
            with self.subTest(body=body):
                self.not_measured(self.t.transform(body))

    def test_failed_validation_is_not_measured(self):
        self.not_measured(self.t.transform(enriched([policy(1, [1])], status="failed")))

    def test_malformed_json_is_not_measured(self):
        out = self.t.transform("{not json")
        self.not_measured(out, raised=True)
        self.assertTrue(out["additionalInfo"]["transformation"]["errors"])

    def test_the_output_contract(self):
        out = self.t.transform([policy(1, [1])])
        self.assertEqual(set(out["transformedResponse"]),
                         {"isDNSPolicyConfigured", "totalPolicies", "policiesWithBlocks", "totalBlockedCategories"})
        self.assertEqual(out["additionalInfo"]["metadata"]["transformationId"], "isDNSPolicyConfigured")


class IsDnsFilteringEnabledTests(NotMeasured, unittest.TestCase):
    KEY = "isDNSFilteringEnabled"

    @classmethod
    def setUpClass(cls):
        cls.t = load(HERE / "isdnsfilteringenabled.py", "dnsfilter_isdnsfilteringenabled")

    def test_a_live_network_passes_and_reports_ip_evidence(self):
        out = self.t.transform([network(1, ip_count=3), network(2, ip_count=0)])
        self.measured(out)
        self.assertIs(self.verdict(out), True)
        self.assertEqual(out["transformedResponse"]["activeNetworks"], 2)
        self.assertEqual(out["transformedResponse"]["networksWithIps"], 1)
        self.assertEqual(out["transformedResponse"]["totalIpCount"], 3)
        self.assertEqual(out["additionalInfo"]["evaluation"]["additionalFindings"], [])

    def test_no_registered_ip_is_named_as_a_finding(self):
        out = self.t.transform(raw(network(1)))
        self.assertIs(self.verdict(out), True)
        self.assertIn("roaming clients", out["additionalInfo"]["evaluation"]["additionalFindings"][0])

    def test_the_raw_body_enriched_body_and_string_read_the_same(self):
        for body in (raw(network(1, 2)), enriched([network(1, 2)]), json.dumps([network(1, 2)]),
                     {"response": raw(network(1, 2))}):
            with self.subTest(body=str(body)[:40]):
                out = self.t.transform(body)
                self.assertIs(self.verdict(out), True)
                self.assertEqual(out["transformedResponse"]["totalIpCount"], 2)

    def test_only_deleted_networks_fail(self):
        """The old transform passed here: a record existed."""
        out = self.t.transform([network(1, 4, deleted_at="2026-01-01T00:00:00Z")])
        self.measured(out)
        self.assertIs(self.verdict(out), False)
        self.assertEqual(out["transformedResponse"]["activeNetworks"], 0)
        self.assertIn("1 deleted", out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_no_networks_fail(self):
        for body in ([], raw(), enriched([])):
            with self.subTest(body=body):
                out = self.t.transform(body)
                self.measured(out)
                self.assertIs(self.verdict(out), False)

    def test_a_deleted_network_beside_a_live_one_is_not_counted(self):
        out = self.t.transform([network(1, 9, deleted_at="2026-01-01T00:00:00Z"), network(2, 1)])
        self.assertIs(self.verdict(out), True)
        self.assertEqual(out["transformedResponse"]["totalIpCount"], 1)

    def test_an_unreadable_record_with_no_live_network_is_not_measured(self):
        self.not_measured(self.t.transform(["garbage", network(1, deleted_at="2026-01-01T00:00:00Z")]))

    def test_records_that_are_not_networks_never_pass(self):
        """Review finding: any dict used to count as a live network, so `[{}]` passed."""
        for body in ([{}], [{"foo": 1}], [{"type": "errors", "detail": "x"}],
                     [{"type": "errors", "attributes": {"name": "x"}}], [{"id": "1", "type": "networks"}],
                     {"data": [{"code": "E1", "detail": "boom"}]}):
            with self.subTest(body=body):
                self.not_measured(self.t.transform(body))

    def test_a_flattened_network_needs_an_id_and_a_network_field(self):
        self.assertIs(self.verdict(self.t.transform([{"id": "1", "name": "Site", "ip_count": 0}])), True)
        self.not_measured(self.t.transform([{"name": "Site"}]))

    def test_odd_ip_counts_are_not_counted(self):
        bad = [network(1), network(2), network(3)]
        bad[0]["attributes"]["ip_count"] = "5"
        bad[1]["attributes"]["ip_count"] = True
        bad[2]["attributes"]["ip_count"] = -2
        out = self.t.transform(bad)
        self.assertEqual(out["transformedResponse"]["totalIpCount"], 0)
        self.assertEqual(out["transformedResponse"]["networksWithIps"], 0)

    def test_bodies_that_prove_nothing_are_not_measured(self):
        for body in ({}, "{}", None, {"error": "Not Authorized"}, {"errors": [{"detail": "Not found"}]},
                     {"hello": "world"}, {"data": {"id": 1}}, 7):
            with self.subTest(body=body):
                self.not_measured(self.t.transform(body))

    def test_failed_validation_is_not_measured(self):
        self.not_measured(self.t.transform(enriched([network(1)], status="failed")))

    def test_malformed_json_is_not_measured(self):
        out = self.t.transform("{not json")
        self.not_measured(out, raised=True)

    def test_the_output_contract(self):
        out = self.t.transform([network(1)])
        self.assertEqual(set(out["transformedResponse"]),
                         {"isDNSFilteringEnabled", "totalNetworks", "activeNetworks", "networksWithIps", "totalIpCount"})
        self.assertEqual(out["additionalInfo"]["metadata"]["transformationId"], "isDNSFilteringEnabled")


@unittest.skipUnless(HAVE_SANDBOX, "RestrictedPython not installed")
class IsDnsPolicyConfiguredInTheProductionSandboxTests(IsDnsPolicyConfiguredTests):
    @classmethod
    def setUpClass(cls):
        sandbox = load(HERE.parents[2] / "tools" / "restricted_sandbox.py", "dnsfilter_policy_sandbox")
        loaded = sandbox.load((HERE / "isdnspolicyconfigured.py").read_text(), "isdnspolicyconfigured.py")
        cls.t = types.SimpleNamespace(transform=loaded["transform"])


@unittest.skipUnless(HAVE_SANDBOX, "RestrictedPython not installed")
class IsDnsFilteringEnabledInTheProductionSandboxTests(IsDnsFilteringEnabledTests):
    @classmethod
    def setUpClass(cls):
        sandbox = load(HERE.parents[2] / "tools" / "restricted_sandbox.py", "dnsfilter_filtering_sandbox")
        loaded = sandbox.load((HERE / "isdnsfilteringenabled.py").read_text(), "isdnsfilteringenabled.py")
        cls.t = types.SimpleNamespace(transform=loaded["transform"])


if __name__ == "__main__":
    unittest.main()
