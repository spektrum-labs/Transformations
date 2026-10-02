"""SentinelOne (2bc425fa) endpoint rules (J.J. 2026-09-29), synthetic agents only.

An agent is judged only when its lastActiveDate is within 15 days of the newest lastActiveDate in the
response; when that newest check-in is itself more than 15 days old the whole fleet is dark and every agent
is stale. Stale agents are left out of the coverage keys and reported as staleAgentCount. A body with no
agent list is not evaluated (None), never a pass. The /agents payload has no phone or tablet machineType
(SentinelOne machineTypes: desktop, laptop, server, kubernetes node, storage, unknown), so there is nothing
to exclude for phones here.
"""
import importlib.util
import unittest
from datetime import datetime, timedelta
from pathlib import Path

KEYS = ["requiredCoveragePercentage", "isEPPEnabled", "isEPPLoggingEnabled", "isEPPConfigured"]
PASS = {"requiredCoveragePercentage": 100.0, "isEPPEnabled": True, "isEPPLoggingEnabled": True, "isEPPConfigured": 100}
# What each key returns for a complete read with no agent in it; a fully stale fleet must match.
# Unevaluated (None), never False or 0% (2026-10-02: an empty fleet proves nothing either way).
EMPTY = {"requiredCoveragePercentage": None, "isEPPEnabled": None, "isEPPLoggingEnabled": None, "isEPPConfigured": None}
NOW = datetime.utcnow()


def load(name):
    spec = importlib.util.spec_from_file_location("window_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent(i, days_ago, good=True):
    return {"id": str(i), "computerName": "host" + str(i), "machineType": "laptop",
            "mitigationMode": "protect" if good else "none", "activeProtection": ["edr"] if good else [],
            "isActive": days_ago < 1, "isUninstalled": not good, "isDecommissioned": False,
            "lastActiveDate": (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}


def ts(agents):
    pagination = {"totalItems": len(agents), "nextCursor": None}
    raw = {"result": {"data": agents, "pagination": pagination,
                      "apiResponse": {"data": agents, "pagination": pagination}}}
    return {"data": raw, "validation": {"status": "skipped", "errors": [], "warnings": []}}


class ActiveWindow(unittest.TestCase):
    mods = {k: load(k) for k in KEYS}

    def run_key(self, key, body):
        return self.mods[key].transform(body)["transformedResponse"]

    def test_fresh_fleet_passes_with_no_stale_agents(self):
        for key in KEYS:
            out = self.run_key(key, ts([agent(1, 0.1), agent(2, 3), agent(3, 14)]))
            self.assertEqual(out[key], PASS[key], key)
            self.assertEqual(out["staleAgentCount"], 0, key)

    def test_dark_fleet_is_all_stale_and_never_passes(self):
        # Every agent last checked in 30+ days ago: today these count as covered.
        for key in KEYS:
            out = self.run_key(key, ts([agent(1, 30), agent(2, 45), agent(3, 120)]))
            self.assertEqual(out[key], EMPTY[key], key)
            self.assertEqual(out["staleAgentCount"], 3, key)

    def test_mixed_fleet_judges_only_fresh_agents(self):
        # The unprotected agent is stale, so it is counted as stale, not judged.
        for key in KEYS:
            out = self.run_key(key, ts([agent(1, 0.1), agent(2, 2), agent(3, 40, good=False)]))
            self.assertEqual(out[key], PASS[key], key)
            self.assertEqual(out["staleAgentCount"], 1, key)

    def test_mixed_fleet_still_fails_on_a_fresh_bad_agent(self):
        for key in KEYS:
            out = self.run_key(key, ts([agent(1, 0.1), agent(2, 1, good=False), agent(3, 40)]))
            self.assertNotEqual(out[key], PASS[key], key)
            self.assertEqual(out["staleAgentCount"], 1, key)

    def test_clock_is_the_newest_check_in_not_the_wall_clock(self):
        # Newest check-in 10 days ago; 20 days ago is within 15 days of it, 30 days ago is not.
        for key in KEYS:
            out = self.run_key(key, ts([agent(1, 10), agent(2, 20), agent(3, 30)]))
            self.assertEqual(out[key], PASS[key], key)
            self.assertEqual(out["staleAgentCount"], 1, key)

    def test_empty_complete_fleet_keeps_its_existing_answer(self):
        for key in KEYS:
            out = self.run_key(key, ts([]))
            self.assertEqual(out[key], EMPTY[key], key)
            self.assertEqual(out["staleAgentCount"], 0, key)

    def test_no_agent_list_is_not_evaluated(self):
        for key in KEYS:
            for body in ({}, None, {"data": {"errors": [{"code": 4010010}]}, "validation": {}}):
                self.assertIsNone(self.run_key(key, body)[key], key)


if __name__ == "__main__":
    unittest.main()
