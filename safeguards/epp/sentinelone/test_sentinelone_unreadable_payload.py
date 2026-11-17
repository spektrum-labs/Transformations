"""SentinelOne getEndpoints transforms: a body cut off in transit, an error object or a malformed envelope is
Not evaluated with a reason, never a crash, a False or a percentage.

Prod, Nov 2026: the agent list sometimes arrived HTTP 200 but cut off part-way (always at a 16 KiB boundary), so
the shared getEndpoints result reached the checks as text that stops mid-JSON. Integration-Service now retries it
and, if still cut off, hands on an error object (errorType incomplete_response). Every getEndpoints transform must
read either shape as Not evaluated and say why. isEPPConfigured used to read any dict without a pagination block as
a complete fleet; it now holds the same complete-read contract as its siblings. Synthetic agents only.
"""
import importlib.util
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

KEYS = ["isEPPEnabled", "isEPPLoggingEnabled", "isEPPConfigured", "isEPPDeployed", "isEPPEnabledForCriticalSystems",
        "requiredCoveragePercentage", "requiredConfigurationPercentage", "isEDRDeployed"]
SEEN = (datetime.utcnow() - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
VALIDATION = {"status": "skipped", "errors": [], "warnings": []}


def load(name):
    spec = importlib.util.spec_from_file_location("unreadable_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent(i, good=True):
    return {"uuid": "agent-" + str(i), "computerName": "host-" + str(i), "machineType": "server",
            "mitigationMode": "protect" if good else "none", "activeProtection": ["edr"] if good else [],
            "isActive": good, "isUninstalled": False, "isDecommissioned": False, "isUpToDate": good,
            "infected": False, "lastActiveDate": SEEN}


def body(agents):
    return {"data": agents, "pagination": {"totalItems": len(agents), "nextCursor": None}}


def ts(raw, validation=VALIDATION):
    return {"data": raw, "validation": validation}


class UnreadablePayload(unittest.TestCase):
    mods = {k: load(k) for k in KEYS}

    def run_key(self, key, payload):
        out = self.mods[key].transform(payload)
        return (out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"],
                out["additionalInfo"]["evaluation"]["failReasons"])

    def assert_not_evaluated(self, payload, reason_part):
        for key in KEYS:
            value, status, reasons = self.run_key(key, payload)
            self.assertIsNone(value, key)
            self.assertEqual(status, "error", key)
            self.assertTrue(any(reason_part in r for r in reasons), (key, reasons))

    def test_cut_off_text_is_not_evaluated_with_the_reason(self):
        cut = json.dumps(body([agent(i) for i in range(30)]))[:500]
        self.assert_not_evaluated(ts(cut), "not valid JSON (500 characters")
        self.assert_not_evaluated(ts(cut.encode()), "not valid JSON (500 characters")
        self.assert_not_evaluated(ts({"result": cut}), "cut off in transit")
        self.assert_not_evaluated(cut, "cut off in transit")

    def test_empty_body_is_not_evaluated_with_an_empty_reason(self):
        for empty in ("", b"", "  "):
            self.assert_not_evaluated(ts(empty), "is empty")

    def test_incomplete_response_error_object_is_not_evaluated(self):
        stub = {"error": True, "errorType": "incomplete_response", "statusCode": 200, "status": "Error",
                "message": "The vendor's response was cut off before it ended, so it could not be read."}
        self.assert_not_evaluated(ts(stub), "SentinelOne returned an error instead of an agent list")

    def test_empty_and_none_are_not_evaluated(self):
        for payload in (ts(""), ts(b""), ts(None), None, ts({})):
            for key in KEYS:
                value, status, _ = self.run_key(key, payload)
                self.assertIsNone(value, (key, payload))
                self.assertEqual(status, "error", (key, payload))

    def test_agent_list_without_pagination_is_not_scored_by_isEPPConfigured(self):
        for raw in ({"data": [agent(1)]}, {"data": [agent(1)], "pagination": "x"}, [agent(1)]):
            value, status, _ = self.run_key("isEPPConfigured", ts(raw))
            self.assertIsNone(value, raw)
            self.assertEqual(status, "error", raw)

    def test_a_validation_block_that_is_not_an_object_does_not_crash(self):
        for key in KEYS:
            value, status, _ = self.run_key(key, ts(body([agent(1)]), validation="not-an-object"))
            self.assertIsNotNone(value, key)
            self.assertEqual(status, "success", key)

    def test_whole_body_as_text_or_bytes_is_scored(self):
        text = json.dumps(body([agent(1), agent(2)]))
        for raw in (text, text.encode()):
            self.assertIs(self.run_key("isEPPEnabled", ts(raw))[0], True)
            self.assertEqual(self.run_key("isEPPConfigured", ts(raw))[0], 100)

    def test_real_shape_passes_and_flipped_fails(self):
        passing = ts({"result": body([agent(1), agent(2)])})
        failing = ts({"result": body([agent(1, good=False), agent(2, good=False)])})
        expect_pass = {"isEPPEnabled": True, "isEPPLoggingEnabled": True, "isEPPConfigured": 100, "isEPPDeployed": True,
                       "isEPPEnabledForCriticalSystems": True}
        expect_fail = {"isEPPEnabled": False, "isEPPLoggingEnabled": False, "isEPPConfigured": 0, "isEPPDeployed": False,
                       "isEPPEnabledForCriticalSystems": False}
        for key, want in expect_pass.items():
            self.assertEqual(self.run_key(key, passing)[0], want, key)
        for key, want in expect_fail.items():
            self.assertEqual(self.run_key(key, failing)[0], want, key)


if __name__ == "__main__":
    unittest.main()
