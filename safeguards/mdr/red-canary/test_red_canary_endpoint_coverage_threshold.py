"""Red Canary isEndpointCoverageValid passes only at full-enough coverage (2026-10-05).

It used to pass when ANY endpoint was monitored, so a tenant with one monitored endpoint in dozens read
"coverage valid". A tool speaks only for what it protects: coverage is now valid only when at least
COVERAGE_VALID_THRESHOLD percent of live (not decommissioned) endpoints are monitored. A live
endpoint with no readable status counts as not covered. A census with no live endpoint is
Unevaluated, never a finding.

All fixtures are synthetic: invented hostnames and ids on example.test.
"""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("rc_ecv_threshold", HERE / "isendpointcoveragevalid.py")
MOD = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MOD)
KEY = "isEndpointCoverageValid"


def endpoint(i, monitoring="monitored", decommissioned="False"):
    attrs = {"display_identifier": "host-%04d.example.test" % i, "hostname": "host-%04d" % i,
             "is_decommissioned": decommissioned, "platform": "Windows"}
    if monitoring is not None:
        attrs["monitoring_status"] = monitoring
    return {"type": "Endpoint", "id": str(9000 + i), "attributes": attrs}


def fleet(monitored, unmonitored, unknown=0, decommissioned=0):
    out = [endpoint(i) for i in range(monitored)]
    out += [endpoint(1000 + i, "unmonitored") for i in range(unmonitored)]
    out += [endpoint(2000 + i, None) for i in range(unknown)]
    out += [endpoint(3000 + i, "unmonitored", "True") for i in range(decommissioned)]
    return {"meta": {"api_version": "v3.0", "total_items": str(len(out))}, "data": out}


def run(payload):
    out = MOD.transform(json.loads(json.dumps(payload)))
    return out["transformedResponse"], out["additionalInfo"]


def test_threshold_is_95():
    assert MOD.COVERAGE_VALID_THRESHOLD == 95


@pytest.mark.parametrize("monitored,unmonitored,expected", [
    (1, 30, False),     # the old defect: one monitored endpoint read "coverage valid"
    (200, 740, False),  # 21.3%
    (181, 19, False),   # 90.5%: below 95
    (94, 6, False),     # 94%: below 95
    (189, 10, False),   # 94.97%: never rounded up
    (95, 5, True),      # exactly 95%
    (97, 3, True),
    (16, 0, True),
])
def test_partial_coverage_fails_and_full_enough_passes(monitored, unmonitored, expected):
    tr, info = run(fleet(monitored, unmonitored))
    assert info["dataCollection"]["status"] == "success"
    assert tr[KEY] is expected
    assert tr["monitoredEndpoints"] == monitored and tr["totalEndpoints"] == monitored + unmonitored
    assert tr["coverageThreshold"] == 95
    reasons = info["evaluation"]["passReasons"] if expected else info["evaluation"]["failReasons"]
    assert reasons and "%d of %d" % (monitored, monitored + unmonitored) in reasons[0]


def test_decommissioned_endpoints_are_not_in_the_denominator():
    tr, _ = run(fleet(19, 1, decommissioned=30))
    assert tr[KEY] is True
    assert (tr["totalEndpoints"], tr["decommissionedEndpoints"], tr["coveragePercentage"]) == (20, 30, 95.0)


def test_unknown_status_counts_as_not_covered():
    tr, info = run(fleet(95, 0, unknown=5))
    assert tr[KEY] is True  # 95 of 100
    tr, info = run(fleet(94, 0, unknown=6))
    assert tr[KEY] is False and tr["unknownStatusEndpoints"] == 6
    assert any("no readable monitoring status" in f for f in info["evaluation"]["additionalFindings"])


def test_only_decommissioned_is_unevaluated_not_a_finding():
    tr, info = run(fleet(0, 0, decommissioned=4))
    assert tr[KEY] is None
    assert info["dataCollection"]["status"] == "error"
