"""Microsoft Foundry (Artificial Intelligence) over one Azure Resource Graph summarize row: isLocalAuthDisabled, isPublicNetworkAccessDisabled.

Fixture shape follows https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources?view=rest-azureresourcegraph-resourcegraph-2022-10-01
("Summarize" / "Basic tenant query" samples).
"""
import importlib.util
from pathlib import Path

import pytest

TOTAL = "resourceCount"
COVERAGE = "subscriptionCount"
FIELDS = ["resourceCount", "localAuthDisabledCount", "publicAccessDisabledCount"]
KEYS = {"isLocalAuthDisabled": ["localAuthDisabledCount", "all"], "isPublicNetworkAccessDisabled": ["publicAccessDisabledCount", "all"]}


def load(name):
    spec = importlib.util.spec_from_file_location("foundry_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = {k: load(k) for k in KEYS}


def summary(total, **counts):
    row = {name: counts.get(name, total) for name in FIELDS}
    row[TOTAL] = total
    row[COVERAGE] = counts.get(COVERAGE, 2)
    return {"totalRecords": 1, "count": 1, "resultTruncated": "false", "facets": [], "data": [row]}


def run(key, payload):
    out = MODULES[key].transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("key", sorted(KEYS))
def test_every_resource_compliant(key):
    assert run(key, summary(3)) == (True, "success")


@pytest.mark.parametrize("key", sorted(KEYS))
def test_partial_compliance(key):
    field, kind = KEYS[key]
    expected = False if kind == "all" else True
    assert run(key, summary(3, **{field: 1})) == (expected, "success")
    assert MODULES[key].transform(summary(3, **{field: 1}))["transformedResponse"][TOTAL] == 3


@pytest.mark.parametrize("key", sorted(KEYS))
def test_subscription_coverage_is_reported(key):
    out = MODULES[key].transform(summary(3, **{COVERAGE: 4}))
    assert out["transformedResponse"][COVERAGE] == 4
    assert "across 4 subscriptions" in " ".join(out["additionalInfo"]["evaluation"]["passReasons"])


@pytest.mark.parametrize("key", sorted(KEYS))
def test_no_compliant_resource_fails(key):
    field, kind = KEYS[key]
    assert run(key, summary(2, **{field: 0})) == (False, "success")


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "arm_403": {"error": {"code": "AuthorizationFailed", "message": "no authorization"}},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"hello": "world"},
    "not_found_404": {"statusCode": 404, "error": "Not Found"},
    "pagination_incomplete": {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429},
    "zero_resources_or_no_reader": summary(0),
    "truncated": dict(summary(3), resultTruncated="true"),
    "two_rows": {"totalRecords": 2, "count": 2, "data": [summary(1)["data"][0], summary(1)["data"][0]]},
    "missing_count": {"totalRecords": 1, "count": 1, "data": [{TOTAL: 3}]},
    "bool_count": summary(True),
    "missing_coverage": {"totalRecords": 1, "count": 1, "data": [{name: 3 for name in FIELDS}]},
    "inconsistent": summary(2, **{name: 5 for name in FIELDS[1:]}),
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("key", sorted(KEYS))
def test_no_evidence_is_unevaluated(key, name):
    assert run(key, NO_EVIDENCE[name]) == (None, "error")


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
