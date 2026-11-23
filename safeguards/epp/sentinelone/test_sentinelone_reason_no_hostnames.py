"""SentinelOne getEndpoints transforms name failing agents by agent id, never by computer name.

Reasons and findings are shown to customers and kept in posture evidence, and a computer name often carries a
person's name. The failing agents are named by SentinelOne uuid (or id), which the console can search. Synthetic
agents only.
"""
import importlib.util
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

KEYS = ["isEPPEnabled", "isEPPLoggingEnabled", "isEPPConfigured", "isEPPEnabledForCriticalSystems",
        "requiredConfigurationPercentage", "isEDRDeployed"]
SEEN = (datetime.utcnow() - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def load(name):
    spec = importlib.util.spec_from_file_location("nohost_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent(i, good, with_uuid=True):
    record = {"id": "9" + str(i), "computerName": "SYNTH-PERSON-" + str(i), "machineType": "server",
              "mitigationMode": "protect" if good else "none", "activeProtection": ["edr"] if good else [],
              "isActive": True, "isUninstalled": False, "isDecommissioned": False, "isUpToDate": good,
              "infected": False, "lastActiveDate": SEEN}
    if with_uuid:
        record["uuid"] = "agent-" + str(i)
    return record


def body(agents):
    return {"data": agents, "pagination": {"totalItems": len(agents), "nextCursor": None}}


class ReasonNamesNoHost(unittest.TestCase):
    mods = {k: load(k) for k in KEYS}

    def test_failing_agents_are_named_by_uuid_not_computer_name(self):
        payload = body([agent(1, True), agent(2, False), agent(3, False)])
        for key in KEYS:
            text = json.dumps(self.mods[key].transform(payload))
            self.assertNotIn("SYNTH-PERSON", text, key)
            self.assertIn("agent-2", text, key)

    def test_agent_without_uuid_falls_back_to_id(self):
        payload = body([agent(1, True), agent(2, False, with_uuid=False)])
        for key in KEYS:
            text = json.dumps(self.mods[key].transform(payload))
            self.assertNotIn("SYNTH-PERSON", text, key)
            self.assertIn("92", text, key)
            self.assertNotIn("agent-2", text, key)


if __name__ == "__main__":
    unittest.main()
