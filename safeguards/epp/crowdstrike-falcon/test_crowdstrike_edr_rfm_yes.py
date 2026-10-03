"""CrowdStrike Falcon isEDRDeployed: a host in Reduced Functionality Mode is not deployed, whatever the spelling.

Falcon reports reduced_functionality_mode as "yes" / "no". The file read only True / "true" as RFM,
so a host reporting "yes" with an agent_version and a sensor_update policy counted as deployed and
could carry the estate to True (a false pass).

Now: "yes", "true" or True (trimmed, any case) is RFM; "no", "false" or False is not; a missing
field (or null) does not block the host, as before. Any other value is unknown: when no host proves
the sensor and an unknown-value host would otherwise count as deployed, the key is None with a
dataCollection error and the reason.

All host data here is synthetic ("estate A")."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location("cs_falcon_" + name + "_rfm_yes", HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EDR = load("isEDRDeployed")
KEY = "isEDRDeployed"
ABSENT = object()


def host(n, rfm="no", sensor_update=True, agent_version="7.40.21309.0"):
    """A host record as GET /devices/entities/devices/v2 returns it (synthetic estate A)."""
    policies = {"prevention": {"policy_id": "prev-a", "applied": True}}
    if sensor_update:
        policies["sensor_update"] = {"policy_id": "su-a", "applied": True}
    record = {"device_id": "estate-a-dev-%04d" % n, "hostname": "estate-a-host-%04d" % n,
              "status": "normal", "platform_name": "Windows", "device_policies": policies,
              "last_seen": "2026-10-02T05:00:00Z"}
    if rfm is not ABSENT:
        record["reduced_functionality_mode"] = rfm
    if agent_version is not None:
        record["agent_version"] = agent_version
    return record


def body(records, total=None):
    page = {"offset": 0, "limit": 5000, "total": len(records) if total is None else total}
    return {"meta": {"query_time": 0.1, "pagination": page, "powered_by": "device-api"},
            "resources": records, "errors": []}


def run(records, **kwargs):
    out = EDR.transform(body(records, **kwargs))
    return out["transformedResponse"], out["additionalInfo"]


def assert_unevaluated(records, reason_contains, **kwargs):
    result, info = run(records, **kwargs)
    assert result[KEY] is None
    assert info["dataCollection"]["status"] == "error"
    assert info["dataCollection"]["errors"] and info["evaluation"]["failReasons"] == info["dataCollection"]["errors"]
    assert reason_contains in info["dataCollection"]["errors"][0], info["dataCollection"]["errors"][0]
    return info


RFM_VALUES = ["yes", "Yes", " YES ", "YES", "yes\n", "true", "True", " TRUE ", True]
NOT_RFM_VALUES = ["no", "No", " NO ", "false", "False", " FALSE ", False]
UNKNOWN_VALUES = ["maybe", "unknown", "", "   ", "y", "n", "enabled", 1, 0, 1.0, [], {}, ["yes"]]


# ---------------------------------------------------------------- RFM spellings: not deployed

@pytest.mark.parametrize("value", RFM_VALUES, ids=repr)
def test_rfm_host_is_not_deployed(value):
    result, info = run([host(i, rfm=value) for i in range(12)])
    assert result == {"isEDRDeployed": False, "totalDevices": 12, "deployedCount": 0,
                      "reducedFunctionalityModeCount": 12}
    assert info["dataCollection"]["status"] == "success"
    assert info["transformation"]["inputSummary"] == {"totalDevices": 12, "deployedCount": 0, "rfmCount": 12}


@pytest.mark.parametrize("value", RFM_VALUES, ids=repr)
def test_rfm_yes_no_longer_carries_the_estate_to_true(value):
    # the false pass: every sensor with a policy is in RFM, and the rest have no sensor_update policy
    records = [host(i, rfm=value) for i in range(3)] + [host(3 + i, sensor_update=False) for i in range(20)]
    result, _ = run(records)
    assert result[KEY] is False
    assert result["deployedCount"] == 0
    assert result["reducedFunctionalityModeCount"] == 3


# ---------------------------------------------------------------- not-RFM spellings: deployed

@pytest.mark.parametrize("value", NOT_RFM_VALUES, ids=repr)
def test_not_rfm_host_is_deployed(value):
    result, info = run([host(i, rfm=value) for i in range(5)])
    assert result == {"isEDRDeployed": True, "totalDevices": 5, "deployedCount": 5,
                      "reducedFunctionalityModeCount": 0}
    assert info["evaluation"]["additionalFindings"] == []
    assert "Reduced Functionality Mode" in info["evaluation"]["passReasons"][0]


# ---------------------------------------------------------------- absent field: today's behaviour

@pytest.mark.parametrize("missing", [ABSENT, None], ids=["key absent", "null"])
def test_absent_rfm_does_not_block_a_deployed_host(missing):
    result, info = run([host(i, rfm=missing) for i in range(4)])
    assert result == {"isEDRDeployed": True, "totalDevices": 4, "deployedCount": 4,
                      "reducedFunctionalityModeCount": 0}
    assert info["transformation"]["inputSummary"] == {"totalDevices": 4, "deployedCount": 4, "rfmCount": 0}


@pytest.mark.parametrize("missing", [ABSENT, None], ids=["key absent", "null"])
def test_absent_rfm_without_sensor_evidence_still_fails(missing):
    result, _ = run([host(i, rfm=missing, sensor_update=False) for i in range(4)])
    assert result[KEY] is False


# ---------------------------------------------------------------- unknown values

@pytest.mark.parametrize("value", UNKNOWN_VALUES, ids=repr)
def test_unknown_rfm_on_the_deciding_host_is_unevaluated(value):
    info = assert_unevaluated([host(0, rfm=value)] + [host(i, sensor_update=False) for i in range(1, 6)],
                              "neither yes/true nor no/false")
    assert info["transformation"]["inputSummary"] == {"totalDevices": 6, "deployedCount": 0, "rfmCount": 0,
                                                      "rfmUnknownCount": 1}


def test_unknown_rfm_on_every_host_is_unevaluated():
    info = assert_unevaluated([host(i, rfm="maybe") for i in range(8)], "8 of them would count as deployed")
    assert '"maybe"' in info["dataCollection"]["errors"][0]


def test_unknown_rfm_beside_rfm_yes_hosts_is_unevaluated():
    assert_unevaluated([host(0, rfm="yes"), host(1, rfm="yes"), host(2, rfm="unknown")], "1 of them")


def test_unknown_rfm_does_not_undo_a_proven_host():
    result, info = run([host(0, rfm="no"), host(1, rfm="maybe"), host(2, rfm=7)])
    assert result == {"isEDRDeployed": True, "totalDevices": 3, "deployedCount": 1,
                      "reducedFunctionalityModeCount": 0}
    assert info["dataCollection"]["status"] == "success"
    assert info["transformation"]["inputSummary"]["rfmUnknownCount"] == 2
    assert info["evaluation"]["additionalFindings"][0].startswith("2 host(s) report a reduced_functionality_mode")
    assert info["evaluation"]["additionalFindings"][0].endswith("not counted as deployed.")


@pytest.mark.parametrize("value", ["maybe", 1, ""], ids=repr)
def test_unknown_rfm_without_sensor_evidence_does_not_decide(value):
    # the host has no sensor_update policy, so it is not deployed whatever its RFM state: False stands
    records = [host(0, rfm=value, sensor_update=False), host(1, rfm=value, agent_version=None),
               host(2, sensor_update=False)]
    result, info = run(records)
    assert result[KEY] is False
    assert info["dataCollection"]["status"] == "success"
    assert info["transformation"]["inputSummary"]["rfmUnknownCount"] == 2
    assert info["evaluation"]["additionalFindings"][0].startswith("2 host(s)")


def test_unknown_value_is_truncated_in_the_reason():
    info = assert_unevaluated([host(0, rfm="x" * 500)], "neither")
    assert ("x" * 41) not in info["dataCollection"]["errors"][0]


def test_only_three_unknown_values_are_quoted():
    info = assert_unevaluated([host(i, rfm="odd-%d" % i) for i in range(6)], "6 host(s)")
    reason = info["dataCollection"]["errors"][0]
    assert '"odd-2"' in reason and '"odd-3"' not in reason


# ---------------------------------------------------------------- mixed estates

def test_mixed_estate_counts_each_spelling():
    records = ([host(i, rfm="no") for i in range(4)] + [host(10 + i, rfm="yes") for i in range(3)]
               + [host(20, rfm=" YES "), host(21, rfm=True), host(22, rfm="true"), host(23, rfm=False),
                  host(24, rfm=ABSENT), host(25, rfm="false"), host(26, sensor_update=False)])
    result, info = run(records)
    assert result == {"isEDRDeployed": True, "totalDevices": 14, "deployedCount": 7,
                      "reducedFunctionalityModeCount": 6}
    assert info["evaluation"]["recommendations"][0].startswith("6 device(s) are in Reduced Functionality Mode")
    assert info["evaluation"]["additionalFindings"] == []


def test_mixed_estate_all_rfm_or_without_policy_fails():
    records = ([host(i, rfm="Yes") for i in range(5)] + [host(10 + i, rfm="no", sensor_update=False) for i in range(5)]
               + [host(20, rfm=ABSENT, agent_version=None), host(21, rfm=True)])
    result, info = run(records)
    assert result == {"isEDRDeployed": False, "totalDevices": 12, "deployedCount": 0,
                      "reducedFunctionalityModeCount": 6}
    assert info["dataCollection"]["status"] == "success"


def test_mixed_estate_with_unknown_and_rfm_yes_only_is_unevaluated():
    records = [host(i, rfm="yes") for i in range(5)] + [host(5, rfm="unknown")] + [host(6, sensor_update=False)]
    info = assert_unevaluated(records, "1 host(s)")
    assert info["transformation"]["inputSummary"] == {"totalDevices": 7, "deployedCount": 0, "rfmCount": 5,
                                                      "rfmUnknownCount": 1}


def test_partial_read_with_only_rfm_yes_hosts_is_unevaluated():
    # #874: a partial read that would say False reads Unevaluated; RFM "yes" now makes it would-be False
    assert_unevaluated([host(i, rfm="yes") for i in range(5)], "partial", total=900)


def test_partial_read_with_a_proven_host_and_unknowns_passes():
    result, info = run([host(0), host(1, rfm="maybe")], total=900)
    assert result[KEY] is True
    findings = info["evaluation"]["additionalFindings"]
    assert findings[0].startswith("1 host(s)") and findings[1].startswith("Partial read")


# ---------------------------------------------------------------- the production sandbox

def test_rfm_rule_runs_in_the_restricted_sandbox():
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import restricted_sandbox
    except ImportError:  # RestrictedPython not installed locally; CI's contract job compiles every file
        return
    edr = restricted_sandbox.load((HERE / "isEDRDeployed.py").read_text())["transform"]
    assert edr(body([host(0, rfm=" YES ")]))["transformedResponse"][KEY] is False
    assert edr(body([host(0, rfm="No")]))["transformedResponse"][KEY] is True
    assert edr(body([host(0, rfm=ABSENT)]))["transformedResponse"][KEY] is True
    assert edr(body([host(0, rfm="maybe")]))["transformedResponse"][KEY] is None
    assert edr(body([host(0), host(1, rfm=3)]))["transformedResponse"][KEY] is True
