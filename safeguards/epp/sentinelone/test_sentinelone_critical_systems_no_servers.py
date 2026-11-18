"""SentinelOne isEPPEnabledForCriticalSystems: no servers is not proof they are protected (ENG-1354).

A fleet of unprotected workstations with no server used to pass ("vacuously passes"). With no
critical system in scope the check is now Not evaluated (value None, dataCollection "error").
Synthetic fixtures only.
"""
import importlib.util
import unittest
from datetime import datetime, timedelta
from pathlib import Path

NOW = datetime.utcnow()


def load():
    spec = importlib.util.spec_from_file_location("s1_critical_eng1354",
                                                  Path(__file__).with_name("isEPPEnabledForCriticalSystems.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent(i, good=True, machine="laptop"):
    return {
        "id": str(1900000000000000000 + i), "uuid": "uuid-" + str(i), "computerName": "HOST-" + str(i),
        "machineType": machine, "mitigationMode": "protect" if good else "none",
        "activeProtection": ["edr", "mitigation"] if good else [],
        "isActive": True, "isUninstalled": False, "isDecommissioned": False,
        "lastActiveDate": (NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


def response(agents):
    pagination = {"totalItems": len(agents), "nextCursor": None}
    return {"data": {"result": {"data": agents, "pagination": pagination}},
            "validation": {"status": "skipped", "errors": [], "warnings": []}}


class CriticalSystemsNoServers(unittest.TestCase):
    mod = load()

    def verdict(self, agents):
        out = self.mod.transform(response(agents))
        return (out["transformedResponse"]["isEPPEnabledForCriticalSystems"],
                out["additionalInfo"]["dataCollection"]["status"])

    def test_unprotected_workstations_and_no_servers_is_not_evaluated(self):
        value, status = self.verdict([agent(i, good=False) for i in range(4)])
        self.assertIsNone(value)
        self.assertEqual(status, "error")

    def test_protected_workstations_and_no_servers_is_not_evaluated(self):
        value, status = self.verdict([agent(i) for i in range(4)])
        self.assertIsNone(value)
        self.assertEqual(status, "error")

    def test_all_servers_protected_passes(self):
        agents = [agent(1, machine="server"), agent(2, machine="server"), agent(3, good=False)]
        self.assertEqual(self.verdict(agents), (True, "success"))

    def test_one_unprotected_server_fails(self):
        agents = [agent(1, machine="server"), agent(2, good=False, machine="server"), agent(3)]
        self.assertEqual(self.verdict(agents), (False, "success"))


if __name__ == "__main__":
    unittest.main()
