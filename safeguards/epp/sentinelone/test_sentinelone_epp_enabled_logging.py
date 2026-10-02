"""SentinelOne isEPPEnabled / isEPPLoggingEnabled judge each agent, not enrolment.

Before 2026-09-29 both returned True whenever pagination.totalItems > 0: any enrolled agent passed,
including one with mitigationMode "none". Agent fields as read by isEPPConfigured and
requiredConfigurationPercentage on GET /web/api/v2.1/agents.
"""
import importlib.util
import unittest
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent(name, mode="protect", active=("edr",)):
    return {"computerName": name, "mitigationMode": mode, "activeProtection": list(active)}


def body(agents, total=None):
    return {"data": agents, "pagination": {"totalItems": len(agents) if total is None else total, "nextCursor": None}}


class EppEnabled(unittest.TestCase):
    m = load("isEPPEnabled")

    def res(self, payload):
        return self.m.transform(payload)["transformedResponse"]

    def test_all_protected_passes(self):
        r = self.res(body([agent("a"), agent("b", "detect")]))
        self.assertIs(r["isEPPEnabled"], True)
        self.assertEqual(r["eppEnabledPercentage"], 100)

    def test_enrolled_agent_with_mitigation_none_fails(self):
        r = self.res(body([agent("a"), agent("b", "none")]))
        self.assertIs(r["isEPPEnabled"], False)
        self.assertEqual(r["eppEnabledPercentage"], 50)

    def test_agent_without_active_protection_fails(self):
        self.assertIs(self.res(body([agent("a", "protect", ())]))["isEPPEnabled"], False)

    def test_empty_fleet_and_error_are_not_evaluated(self):
        # An empty complete read proves nothing either way: None, never False (2026-10-02).
        self.assertIsNone(self.res(body([]))["isEPPEnabled"])
        # An error or an empty body is not a read: None with a dataCollection error (2026-09-29 complete-read guard).
        self.assertIsNone(self.res({"errors": [{"code": 4010010, "title": "Authentication Failed"}]})["isEPPEnabled"])
        self.assertIsNone(self.res({})["isEPPEnabled"])


class EppLogging(unittest.TestCase):
    m = load("isEPPLoggingEnabled")

    def res(self, payload):
        return self.m.transform(payload)["transformedResponse"]

    def test_all_edr_passes(self):
        r = self.res(body([agent("a"), agent("b")]))
        self.assertIs(r["isEPPLoggingEnabled"], True)
        self.assertEqual(r["eppLoggingPercentage"], 100)

    def test_enrolled_agent_without_edr_fails(self):
        r = self.res(body([agent("a"), agent("b", "protect", ("static",))]))
        self.assertIs(r["isEPPLoggingEnabled"], False)
        self.assertEqual(r["agentsWithEdrLogging"], 1)

    def test_enrolment_count_alone_never_passes(self):
        # 0 agents read of 40 enrolled is a partial read: not scored (None), never a pass.
        self.assertIsNone(self.res({"data": [], "pagination": {"totalItems": 40}})["isEPPLoggingEnabled"])


if __name__ == "__main__":
    unittest.main()
