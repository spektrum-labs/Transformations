"""SentinelOne Vigilance MDR transforms: real verdicts on complete reads, None on anything else."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("s1_vigilance_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def agent(i, active=True, up_to_date=True, encrypted=True, uninstalled=False, last="2999-01-01T00:00:00.000000Z"):
    return {"id": str(i), "isActive": active, "isUpToDate": up_to_date, "encryptedApplications": encrypted,
            "isUninstalled": uninstalled, "isDecommissioned": False, "lastActiveDate": last}


def threat(i, status="unresolved", verdict="undefined", mitigation="active"):
    return {"id": str(i), "threatInfo": {"incidentStatus": status, "analystVerdict": verdict,
                                         "mitigationStatus": mitigation, "confidenceLevel": "malicious"}}


def body(items, total=None, next_cursor=None):
    pagination = {"totalItems": len(items) if total is None else total, "nextCursor": next_cursor}
    return {"data": {"data": items, "pagination": pagination, "apiResponse": {"data": items, "pagination": pagination}},
            "validation": {"status": "skipped", "errors": [], "warnings": []}}


def value(key, payload):
    return load(key)(payload)["transformedResponse"][key]


GOOD_AGENTS = [agent(1), agent(2), agent(3), agent(4)]
MIXED_AGENTS = [agent(1), agent(2, active=False, up_to_date=False, encrypted=False),
                agent(3, last="2000-01-01T00:00:00Z"), agent(4, uninstalled=True)]

AGENT_CASES = [
    ("isEDRAgentActive", True, True),
    ("assetInventoryCoveragePercentage", 100.0, 66.67),
    ("agentUpToDatePercentage", 100.0, 66.67),
    ("diskEncryptionCoveragePercentage", 100.0, 66.67),
    ("staleAgentOfflineCount", 0, 2),
]


@pytest.mark.parametrize("key,good,mixed", AGENT_CASES)
def test_agent_keys_measure_a_complete_read(key, good, mixed):
    assert value(key, body(GOOD_AGENTS)) == good
    assert value(key, body(MIXED_AGENTS)) == mixed


def test_no_active_agent_is_false():
    assert value("isEDRAgentActive", body([agent(1, active=False)])) is False
    assert value("isEDRAgentActive", body([])) is False


THREAT_KEYS = ["openMDRCasesCount", "maliciousVerdictOpenIncidentsCount"]


def test_open_threat_counts():
    threats = [threat(1, verdict="true_positive"), threat(2, status="in_progress"), threat(3, status="resolved")]
    assert value("openMDRCasesCount", body(threats)) == 2
    assert value("maliciousVerdictOpenIncidentsCount", body(threats)) == 1
    assert value("openMDRCasesCount", body([])) == 0
    assert value("maliciousVerdictOpenIncidentsCount", body([])) == 0


def test_threat_without_incident_status_is_not_scored():
    assert value("openMDRCasesCount", body([{"id": "1", "threatInfo": {}}])) is None


def test_mitigated_count_uses_server_total():
    key = "completedRemediationActionsCount"
    assert value(key, body([threat(1, status="resolved", mitigation="mitigated")], total=7)) == 7
    assert value(key, body([], total=0)) == 0
    assert value(key, body([threat(1, mitigation="active")], total=7)) is None


NO_EVIDENCE = [
    None,
    {},
    [],
    "",
    {"errors": [{"code": 4010010, "title": "Authentication Failed"}]},
    {"error": True, "message": "Unauthorized", "status_code": 401},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
]
ALL_KEYS = [c[0] for c in AGENT_CASES] + THREAT_KEYS + ["completedRemediationActionsCount"]


@pytest.mark.parametrize("key", ALL_KEYS)
@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(key, payload):
    out = load(key)(payload)
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("key", [c[0] for c in AGENT_CASES] + THREAT_KEYS)
def test_partial_read_is_not_scored(key):
    items = GOOD_AGENTS if key not in THREAT_KEYS else [threat(1)]
    assert value(key, body(items, total=5000)) is None
    assert value(key, body(items, next_cursor="abc")) is None


def test_inventory_coverage_counts_installed_agents_that_are_offline():
    """A run at night: most agents asleep (isActive=false) but installed. Coverage is not about who is online."""
    key = "assetInventoryCoveragePercentage"
    night = [agent(i, active=(i < 3)) for i in range(20)]
    out = load(key)(body(night))
    assert out["transformedResponse"][key] == 100.0
    assert out["transformedResponse"]["installedAgents"] == 20
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_inventory_coverage_falls_for_uninstalled_and_skips_stale():
    key = "assetInventoryCoveragePercentage"
    recent = "2999-01-01T00:00:00Z"
    agents = [agent(1, active=False, last=recent), agent(2, uninstalled=True, last=recent),
              agent(3, uninstalled=True, last=recent), agent(4, last="2998-01-01T00:00:00Z")]
    out = load(key)(body(agents))["transformedResponse"]
    assert out[key] == 33.33
    assert out["staleAgentCount"] == 1


def test_inventory_coverage_all_stale_is_not_measured():
    key = "assetInventoryCoveragePercentage"
    out = load(key)(body([agent(1, last="2000-01-01T00:00:00Z"), agent(2, last="2000-01-02T00:00:00Z")]))
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


# ---- follow-up review of #1442: a missing or null isUninstalled is not evidence of an installed agent

def unflagged(i, flag="missing", active=None):
    a = agent(i, active=active)
    if flag == "missing":
        del a["isUninstalled"]
    else:
        a["isUninstalled"] = flag
    if active is None:
        del a["isActive"]
    return a


@pytest.mark.parametrize("flag", ["missing", None, "", "unknown"])
def test_inventory_coverage_one_unflagged_agent_is_not_measured(flag):
    # Reviewer's case: one agent with no isUninstalled read 100.0 (it read 0.0 before #1442).
    out = load("assetInventoryCoveragePercentage")(body([unflagged(1, flag)]))
    assert out["transformedResponse"]["assetInventoryCoveragePercentage"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_inventory_coverage_unflagged_agents_are_left_out_and_reported():
    key = "assetInventoryCoveragePercentage"
    out = load(key)(body([agent(1), agent(2, uninstalled=True), unflagged(3), unflagged(4, None)]))
    result = out["transformedResponse"]
    assert result[key] == 50.0
    assert result["knownEndpoints"] == 2 and result["installedAgents"] == 1 and result["unreadAgentCount"] == 2
    assert any("unreadAgentCount" in f for f in out["additionalInfo"]["evaluation"]["additionalFindings"])


def test_inventory_coverage_explicit_false_flag_and_active_agent_count_as_installed():
    key = "assetInventoryCoveragePercentage"
    assert value(key, body([agent(1, uninstalled="false"), agent(2, active=False)])) == 100.0
    # No isUninstalled, but isActive true: the agent is reporting in, the evidence the old code used.
    assert value(key, body([unflagged(1, active=True)])) == 100.0
    assert value(key, body([unflagged(1, active=False)])) is None
