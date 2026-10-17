"""Claude Compliance API criteria: answer contract tests.

True only from read evidence that shows the control; False only from read evidence that
shows it is absent; None (not evaluated, dataCollection.status "error") for everything
else. All fixtures are synthetic.
"""
import importlib.util
import unittest
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def iso(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def activity(days_ago, kind="compliance_api_accessed"):
    return {"id": "activity_test", "created_at": iso(days_ago), "type": kind,
            "actor": {"type": "api_actor", "api_key_id": "apikey_test", "ip_address": "192.0.2.1"}}


def rows(**kv):
    return [{"name": k, "type": "boolean", "value": v} for k, v in kv.items()]


def key(name, scopes, active=True):
    return {"type": "compliance_api_key", "id": "apikey_" + name, "name": name, "scopes": scopes,
            "is_active": active, "created_at": "2026-01-01T00:00:00Z", "created_by_id": None,
            "expires_at": None}


RELAY_401 = {"result": {"integrationName": "test", "errorMessage": "invalid x-api-key", "vendorStatus": 401}}
RELAY_403 = {"result": {"integrationName": "test", "errorMessage": "Missing required scopes", "vendorStatus": 403}}
GENERIC_404 = {"error": "not_found", "statusCode": 404, "message": "not found"}
# Anthropic's documented 400 body while the Compliance API is off, in the relay and generic shapes.
NOT_ENABLED_RELAY = {"result": {"integrationName": "test", "vendorStatus": 400,
                                "errorMessage": "Compliance API is not enabled for this organization"}}
NOT_ENABLED_GENERIC = {"statusCode": 400, "error": {"type": "invalid_request_error",
                                                    "message": "Compliance API is not enabled for this organization"}}
OTHER_400 = {"result": {"integrationName": "test", "vendorStatus": 400, "errorMessage": "Unknown query parameter"}}
NO_EVIDENCE = ([], {}, None, "{}", "[]", "<html>502</html>")


class Base(unittest.TestCase):
    NAME = None
    KEY = None

    @classmethod
    def setUpClass(cls):
        cls.t = load(cls.NAME)

    def run_t(self, payload):
        return self.t.transform(payload)

    def value(self, payload):
        return self.run_t(payload)["transformedResponse"][self.KEY]

    def assert_not_evaluated(self, payload):
        out = self.run_t(payload)
        self.assertIsNone(out["transformedResponse"][self.KEY], repr(payload)[:80])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error", repr(payload)[:80])

    def check_refusals_and_empties(self):
        for payload in (RELAY_401, RELAY_403, GENERIC_404, OTHER_400) + NO_EVIDENCE:
            self.assert_not_evaluated(payload)


class AuditLoggingTests(Base):
    NAME = "isauditloggingenabled"
    KEY = "isAuditLoggingEnabled"

    def test_recent_record_passes(self):
        self.assertIs(self.value([activity(0)]), True)
        self.assertIs(self.value({"data": [activity(6)], "has_more": True}), True)

    def test_stale_record_fails(self):
        out = self.run_t([activity(30)])
        self.assertIs(out["transformedResponse"][self.KEY], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_newest_record_wins_regardless_of_order(self):
        self.assertIs(self.value([activity(40), activity(1)]), True)

    def test_unreadable_timestamp_is_not_evaluated(self):
        self.assert_not_evaluated([{"type": "x", "created_at": "yesterday"}])
        self.assert_not_evaluated(["not a record"])

    def test_refusals_and_empty_bodies_are_not_evaluated(self):
        self.check_refusals_and_empties()

    def test_api_turned_off_fails(self):
        for payload in (NOT_ENABLED_RELAY, NOT_ENABLED_GENERIC):
            out = self.run_t(payload)
            self.assertIs(out["transformedResponse"][self.KEY], False)
            self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_actor_details_are_not_echoed(self):
        out = self.run_t([activity(0)])
        self.assertNotIn("192.0.2.1", str(out))


class AccessTransparencyTests(Base):
    NAME = "isaccesstransparencyenabled"
    KEY = "isAccessTransparencyEnabled"

    def test_read_true_passes(self):
        self.assertIs(self.value(rows(access_transparency_enabled=True)), True)

    def test_read_false_fails(self):
        self.assertIs(self.value(rows(access_transparency_enabled=False, sso_enabled=True)), False)

    def test_missing_row_is_not_evaluated_never_off(self):
        self.assert_not_evaluated(rows(sso_enabled=True))

    def test_non_boolean_value_is_not_evaluated(self):
        self.assert_not_evaluated(rows(access_transparency_enabled=None))
        self.assert_not_evaluated(rows(access_transparency_enabled="maybe"))

    def test_api_turned_off_is_not_evaluated_here(self):
        self.assert_not_evaluated(NOT_ENABLED_RELAY)

    def test_full_body_shape_is_read(self):
        body = {"type": "effective_organization_settings", "organization_id": "00000000-0000-0000-0000-000000000000",
                "settings": rows(access_transparency_enabled=True), "api_keys": []}
        self.assertIs(self.value(body), True)

    def test_refusals_and_empty_bodies_are_not_evaluated(self):
        self.check_refusals_and_empties()


class KeyScopeSeparationTests(Base):
    NAME = "iscompliancekeyscopeseparated"
    KEY = "isComplianceKeyScopeSeparated"

    def test_read_only_keys_pass(self):
        keys = [key("siem", ["read:compliance_activities", "read:compliance_org_data"])]
        self.assertIs(self.value(keys), True)

    def test_separate_read_and_delete_keys_pass(self):
        keys = [key("reader", ["read:compliance_user_data"]), key("deleter", ["delete:compliance_user_data"])]
        self.assertIs(self.value(keys), True)

    def test_key_that_reads_and_deletes_fails(self):
        keys = [key("siem", ["read:compliance_activities"]),
                key("ediscovery", ["read:compliance_user_data", "delete:compliance_user_data"])]
        out = self.run_t(keys)
        self.assertIs(out["transformedResponse"][self.KEY], False)
        self.assertIn("ediscovery", out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_deactivated_combined_key_does_not_fail(self):
        keys = [key("siem", ["read:compliance_activities"]),
                key("old", ["read:compliance_user_data", "delete:compliance_user_data"], active=False)]
        self.assertIs(self.value(keys), True)

    def test_unreadable_scopes_are_not_evaluated(self):
        self.assert_not_evaluated([key("siem", None)])

    def test_combined_key_fails_even_with_another_unreadable(self):
        keys = [key("odd", None), key("both", ["read:compliance_org_data", "delete:compliance_user_data"])]
        self.assertIs(self.value(keys), False)

    def test_no_active_key_is_not_evaluated(self):
        self.assert_not_evaluated([key("old", ["read:compliance_activities"], active=False)])

    def test_mapped_dict_shape_is_read(self):
        self.assertIs(self.value({"data": [key("siem", ["read:compliance_activities"])]}), True)

    def test_refusals_and_empty_bodies_are_not_evaluated(self):
        self.check_refusals_and_empties()


class ComplianceAPIEnabledTests(Base):
    NAME = "iscomplianceapienabled"
    KEY = "isComplianceAPIEnabled"

    def test_readable_feed_passes(self):
        self.assertIs(self.value([activity(0, "claude_chat_created")]), True)

    def test_refused_call_is_not_evaluated_not_failed(self):
        self.check_refusals_and_empties()

    def test_api_turned_off_fails(self):
        for payload in (NOT_ENABLED_RELAY, NOT_ENABLED_GENERIC):
            self.assertIs(self.value(payload), False)

    def test_scope_text_names_real_scopes(self):
        out = self.run_t(RELAY_403)
        text = " ".join(out["additionalInfo"]["evaluation"]["recommendations"])
        self.assertIn("read:compliance_org_data", text)
        self.assertNotIn("read:org_audit", text)


if __name__ == "__main__":
    unittest.main()
