"""Microsoft Defender for Cloud Apps (Cloud Security): openHighSeverityAlertCount, noHighFindings.

Fixtures follow the Microsoft Graph List alerts_v2 response
(https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0), filtered server-side to
serviceSource microsoftDefenderForCloudApps, severity high, status new or inProgress; IS merges every page into value.
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


def alert(i, status="new", severity="high", source="microsoftDefenderForCloudApps"):
    return {"@odata.type": "#microsoft.graph.security.alert", "id": "da6375512276775608%02d" % i, "status": status,
            "severity": severity, "serviceSource": source, "title": "Impossible travel activity"}


def alerts(total, statuses=("new", "inProgress")):
    return {"value": [alert(i, status=statuses[i % len(statuses)]) for i in range(total)]}


def run(module, key, payload):
    out = module.transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def test_open_high_alerts_counted():
    assert run(COUNT, "openHighSeverityAlertCount", alerts(7)) == (7, "success")
    assert run(NONE_HIGH, "noHighFindings", alerts(7)) == (False, "success")


def test_zero_open_high_alerts():
    assert run(COUNT, "openHighSeverityAlertCount", alerts(0)) == (0, "success")
    assert run(NONE_HIGH, "noHighFindings", alerts(0)) == (True, "success")


def test_merged_pages_are_all_counted():
    """IS link pagination merges pages into value and drops the nextLink on the last page."""
    payload = {"value": [alert(i) for i in range(250)]}
    assert run(COUNT, "openHighSeverityAlertCount", payload) == (250, "success")
    assert run(NONE_HIGH, "noHighFindings", payload) == (False, "success")


def test_case_of_enum_values_does_not_matter():
    payload = {"value": [alert(1, status="InProgress", severity="High", source="MicrosoftDefenderForCloudApps")]}
    assert run(COUNT, "openHighSeverityAlertCount", payload) == (1, "success")


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "graph_403": {"error": {"code": "Forbidden", "message": "Missing role SecurityAlert.Read.All"}},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"hello": "world"},
    "not_found_404": {"statusCode": 404, "error": "Not Found"},
    "throttled_429": {"statusCode": 429, "error": "TooManyRequests"},
    "pagination_incomplete": {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429},
    "next_link_left": {"value": [alert(1)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=x"},
    "value_not_list": {"value": {"id": "x"}},
    "item_not_dict": {"value": ["x"]},
    "other_source": {"value": [alert(1, source="microsoftDefenderForEndpoint")]},
    "medium_alert": {"value": [alert(1, severity="medium")]},
    "resolved_alert": {"value": [alert(1, status="resolved")]},
    "missing_fields": {"value": [{"id": "x"}]},
    "old_mdca_api_shape": {"data": [], "total": 0, "hasNext": False, "moreThanTotal": False},
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
