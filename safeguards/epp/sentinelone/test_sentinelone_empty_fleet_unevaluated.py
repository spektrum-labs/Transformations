"""SentinelOne (2bc425fa): an empty agent list is Unevaluated with the reason, never FAIL or 0%.

Read-only fleet run, 2 Oct 2026 17:37 ET: at Collaborative Fund GET /web/api/v2.1/agents returned a complete read
with no agents ("No SentinelOne agents were returned"). isEPPConfigured already read Not evaluated, but
requiredCoveragePercentage read a measured 0.0 and isEPPEnabled / isEPPLoggingEnabled a measured False, so the
passport went from 6 passing to 2 on an empty list. The same shape read FAIL at Padilla Law, ValueSelling, ATX
Venture Partners, HeyApril and MEASURE.

The contract every getEndpoints transform now holds, through the Token-Service envelope:
- empty complete read, error body, partial read: value None and dataCollection "error" with the
  reason (Token-Service renders that as "Not evaluated", no gap);
- a real tenant whose agents fail still reads a measured FAIL, and one whose agents pass still passes.
Agent shapes follow SentinelOne's GET /agents fields the transforms read.
"""
import importlib.util
import unittest
from datetime import datetime, timedelta
from pathlib import Path

KEYS = ["requiredCoveragePercentage", "requiredConfigurationPercentage", "isEPPEnabled", "isEPPLoggingEnabled",
        "isEPPConfigured", "isEPPEnabledForCriticalSystems", "isEPPDeployed"]
NOW = datetime.utcnow()


def load(name):
    spec = importlib.util.spec_from_file_location("empty_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent(i, good=True, days_ago=0.2, machine="laptop"):
    return {
        "id": str(1900000000000000000 + i), "uuid": "uuid-" + str(i), "computerName": "HOST-" + str(i),
        "machineType": machine, "osName": "Windows 11 Pro", "agentVersion": "24.1.4.257", "siteName": "Default site",
        "mitigationMode": "protect" if good else "none",
        "mitigationModeSuspicious": "detect",
        "activeProtection": ["edr", "mitigation"] if good else [],
        "isActive": True, "isUninstalled": not good, "isDecommissioned": False, "isUpToDate": True,
        "infected": False, "networkStatus": "connected",
        "lastActiveDate": (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


def is_response(agents, total=None, cursor=None):
    pagination = {"totalItems": len(agents) if total is None else total, "nextCursor": cursor}
    return {"result": {"data": agents, "pagination": pagination,
                       "apiResponse": {"data": agents, "pagination": pagination}}}


def ts(raw):
    return {"data": raw, "validation": {"status": "skipped", "errors": [], "warnings": []}}


class EmptyFleetUnevaluated(unittest.TestCase):
    mods = {k: load(k) for k in KEYS}

    def run_key(self, key, payload):
        out = self.mods[key].transform(payload)
        return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]

    def assert_unevaluated(self, key, payload, needle):
        value, collection = self.run_key(key, payload)
        self.assertIsNone(value, key)
        self.assertEqual(collection["status"], "error", key)
        self.assertTrue(any(needle in str(e) for e in collection["errors"]), (key, collection["errors"]))

    def test_empty_complete_read_is_unevaluated_with_reason(self):
        for key in KEYS:
            self.assert_unevaluated(key, ts(is_response([])), "No SentinelOne agents were returned")

    def test_empty_read_in_legacy_input_format_is_unevaluated(self):
        for key in KEYS:
            value, collection = self.run_key(key, is_response([]))
            self.assertIsNone(value, key)
            self.assertEqual(collection["status"], "error", key)

    def test_error_body_is_unevaluated(self):
        bodies = [ts({"result": {"errors": [{"code": 4010010, "title": "Authentication Failed"}]}}),
                  ts({"error": True, "statusCode": 412, "message": "Required integration credentials are not connected"}),
                  ts({}), ts(None)]
        for key in KEYS:
            for body in bodies:
                value, collection = self.run_key(key, body)
                self.assertIsNone(value, (key, body))
                self.assertEqual(collection["status"], "error", (key, body))

    def test_partial_read_is_unevaluated(self):
        page = [agent(i) for i in range(5)]
        for key in KEYS:
            value, collection = self.run_key(key, ts(is_response(page, total=12, cursor="eyJpZCI6IDV9")))
            self.assertIsNone(value, key)
            self.assertEqual(collection["status"], "error", key)

    def test_real_tenant_with_failing_agents_still_fails(self):
        fleet = [agent(1), agent(2), agent(3, good=False), agent(4, good=False, machine="server")]
        expected = {"requiredCoveragePercentage": 50.0, "requiredConfigurationPercentage": 50.0,
                    "isEPPEnabled": False, "isEPPLoggingEnabled": False, "isEPPConfigured": 50,
                    "isEPPEnabledForCriticalSystems": False}
        for key, want in expected.items():
            value, collection = self.run_key(key, ts(is_response(fleet)))
            self.assertEqual(value, want, key)
            self.assertEqual(collection["status"], "success", key)

    def test_real_tenant_with_no_deployed_agent_fails_deployment(self):
        fleet = [dict(agent(1), isActive=False), dict(agent(2), isUninstalled=True)]
        value, collection = self.run_key("isEPPDeployed", ts(is_response(fleet)))
        self.assertIs(value, False)
        self.assertEqual(collection["status"], "success")

    def test_real_tenant_with_protected_agents_still_passes(self):
        fleet = [agent(1), agent(2), agent(3, machine="server")]
        expected = {"requiredCoveragePercentage": 100.0, "requiredConfigurationPercentage": 100.0,
                    "isEPPEnabled": True, "isEPPLoggingEnabled": True, "isEPPConfigured": 100,
                    "isEPPEnabledForCriticalSystems": True, "isEPPDeployed": True}
        for key, want in expected.items():
            value, collection = self.run_key(key, ts(is_response(fleet)))
            self.assertEqual(value, want, key)
            self.assertEqual(collection["status"], "success", key)


if __name__ == "__main__":
    unittest.main()
