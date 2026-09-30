"""Windows Defender One-Click patchCompliancePercentage from getPatchComplianceStatus (Defender TVM)."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "mdepcp", Path(__file__).with_name("microsoft_endpoint_patchcompliancepercentage.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def body(assessed, crit, crit_high):
    return {"Schema": [{"Name": "AssessedDevices", "Type": "Int64"}],
            "Results": [{"AssessedDevices": assessed, "DevicesWithOverdueCritical": crit,
                         "DevicesWithOverdueCriticalOrHigh": crit_high}]}


def run(payload):
    out = m.transform(payload)
    return out["transformedResponse"]["patchCompliancePercentage"], out["additionalInfo"]["dataCollection"]["status"]


def test_fully_patched_is_100():
    assert run(body(40, 0, 0)) == (100.0, "success")


def test_percentage_rounds_down():
    # 37/40 = 92.5; 2/3 = 66.66.. -> 66.6 (never rounded up)
    assert run(body(40, 1, 3)) == (92.5, "success")
    assert run(body(3, 0, 1)) == (66.6, "success")


def test_just_below_threshold_is_not_reported_at_it():
    # 189/199 = 94.97.. must not become 95.0
    assert run(body(199, 0, 10))[0] == 94.9


def test_wrapped_body():
    assert run({"apiResponse": body(10, 0, 1)}) == (90.0, "success")


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "error": {"error": {"code": "Forbidden", "message": "Missing AdvancedQuery.Read.All"}},
    "no_rows": {"Results": []},
    "alerts_body": {"value": [{"id": "da1", "severity": "High"}]},
    "no_inventory": body(0, 0, 0),
    "missing_counts": {"Results": [{"AssessedDevices": 5}]},
    "bool_counts": body(True, 0, False),
    "inconsistent": body(5, 0, 9),
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_no_evidence_is_unevaluated(name):
    assert run(NO_EVIDENCE[name]) == (None, "error")
