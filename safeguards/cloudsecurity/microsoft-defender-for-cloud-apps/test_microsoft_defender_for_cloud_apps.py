"""Microsoft Defender for Cloud Apps (Cloud Security): openHighSeverityAlertCount, noHighFindings.

Fixtures follow the List alerts response on https://learn.microsoft.com/en-us/defender-cloud-apps/api-alerts-list .
"""
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location("mdca_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COUNT = load("openHighSeverityAlertCount")
NONE_HIGH = load("noHighFindings")


def alerts(total, more=False):
    data = [{"_id": "603f704aaf7417985bbf3b22", "title": "Impossible travel", "severityValue": 2,
             "resolutionStatusValue": 0}] if total else []
    return {"data": data, "hasNext": total > 1, "max": 1, "total": total, "moreThanTotal": more}


def run(module, key, payload):
    out = module.transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def test_open_high_alerts_counted():
    assert run(COUNT, "openHighSeverityAlertCount", alerts(7)) == (7, "success")
    assert run(NONE_HIGH, "noHighFindings", alerts(7)) == (False, "success")


def test_zero_open_high_alerts():
    assert run(COUNT, "openHighSeverityAlertCount", alerts(0)) == (0, "success")
    assert run(NONE_HIGH, "noHighFindings", alerts(0)) == (True, "success")


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "mdca_403": {"error": {"code": "Forbidden", "message": "Missing Investigation.read"}},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"hello": "world"},
    "not_found_404": {"statusCode": 404, "error": "Not Found"},
    "pagination_incomplete": {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429},
    "no_total": {"data": [], "hasNext": False},
    "lower_bound": alerts(5000, more=True),
    "bool_total": {"data": [], "total": False},
}
CASES = [(COUNT, "openHighSeverityAlertCount"), (NONE_HIGH, "noHighFindings")]


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("module,key", CASES, ids=[k for m, k in CASES])
def test_no_evidence_is_unevaluated(module, key, name):
    assert run(module, key, NO_EVIDENCE[name]) == (None, "error")


def test_every_transform_reports_schema_version_2_0():
    """transformedResponse envelope is the CONTRIBUTING.md schemaVersion 2.0 one, on answers and on errors."""
    import importlib.util as iu
    for path in sorted(Path(__file__).parent.glob("*.py")):
        if path.name.startswith("test_"):
            continue
        spec = iu.spec_from_file_location("schema_" + path.stem, path)
        module = iu.module_from_spec(spec)
        spec.loader.exec_module(module)
        out = module.transform({})
        assert out["additionalInfo"]["metadata"]["schemaVersion"] == "2.0", path.name
        assert set(out["additionalInfo"]) == {"dataCollection", "validation", "transformation", "evaluation", "metadata"}
