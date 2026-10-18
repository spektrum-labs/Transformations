"""MDR coverage counts only a managed service: the "mtr" product or an explicit mdrManaged true.

The "xdr" product is the self-service XDR licence, not a managed service, so an endpoint that
has only "xdr" is not MDR coverage; it is counted on its own as information. A missing or null
mdrManaged is not MDR either. Both mdr_transform.py and epp_transform.py carry the same rule.
Synthetic endpoints in the Sophos /endpoint/v1/endpoints shape."""
import importlib.util
import pathlib
from datetime import datetime

import pytest

HERE = pathlib.Path(__file__).parent
FILES = ["mdr_transform.py", "epp_transform.py"]
XDR_KEY = "XDR (self-service, information only)"
# epp_transform ignores endpoints not seen recently, so build a fresh timestamp each run.
NOW = datetime.utcnow().isoformat()[:19] + "Z"


def run(name, items):
    spec = importlib.util.spec_from_file_location("sophos_" + name[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform({"items": items})


def endpoint(eid, products, **extra):
    item = {"id": eid, "type": "computer", "lastSeenAt": NOW,
            "assignedProducts": [{"code": c, "status": "installed"} for c in products],
            "health": {"services": {"serviceDetails": []}}}
    item.update(extra)
    return item


def counters(out):
    return out["additionalInfo"]["transformation"]["inputSummary"]["safeguardCounters"]


@pytest.mark.parametrize("name", FILES)
def test_xdr_only_endpoint_is_not_mdr(name):
    out = run(name, [endpoint("e1", ["endpointProtection", "xdr"])])
    assert out["transformedResponse"]["MDR"] == 0
    assert out["transformedResponse"]["isMDREnabled"] is False
    assert counters(out)["MDR"] == 0
    assert counters(out)[XDR_KEY] == 1


@pytest.mark.parametrize("name", FILES)
def test_managed_threat_response_product_is_mdr(name):
    out = run(name, [endpoint("e1", ["endpointProtection", "mtr"])])
    assert out["transformedResponse"]["MDR"] == 100
    assert out["transformedResponse"]["isMDREnabled"] is True
    assert counters(out)["MDR"] == 1
    assert counters(out)[XDR_KEY] == 0


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", [True, "true", "True"])
def test_explicit_mdr_managed_true_is_mdr(name, flag):
    out = run(name, [endpoint("e1", ["endpointProtection"], mdrManaged=flag)])
    assert out["transformedResponse"]["MDR"] == 100
    assert out["transformedResponse"]["isMDREnabled"] is True


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", [None, False, "false", "", "unknown", 0])
def test_null_or_false_mdr_managed_is_not_mdr(name, flag):
    out = run(name, [endpoint("e1", ["endpointProtection"], mdrManaged=flag)])
    assert out["transformedResponse"]["MDR"] == 0
    assert out["transformedResponse"]["isMDREnabled"] is False


@pytest.mark.parametrize("name", FILES)
def test_absent_mdr_managed_is_not_mdr(name):
    out = run(name, [endpoint("e1", ["endpointProtection"])])
    assert out["transformedResponse"]["MDR"] == 0
    assert out["transformedResponse"]["isMDREnabled"] is False


@pytest.mark.parametrize("name", FILES)
def test_xdr_with_explicit_false_is_not_mdr(name):
    out = run(name, [endpoint("e1", ["endpointProtection", "xdr"], mdrManaged=False)])
    assert out["transformedResponse"]["MDR"] == 0
    assert counters(out)[XDR_KEY] == 1


@pytest.mark.parametrize("name", FILES)
def test_mtr_and_xdr_together_count_once_each(name):
    out = run(name, [endpoint("e1", ["endpointProtection", "mtr", "xdr"])])
    assert counters(out)["MDR"] == 1
    assert counters(out)[XDR_KEY] == 1


@pytest.mark.parametrize("name", FILES)
def test_mixed_fleet_scores_only_managed_endpoints(name):
    items = [endpoint("e1", ["endpointProtection", "mtr"]),
             endpoint("e2", ["endpointProtection", "xdr"]),
             endpoint("e3", ["endpointProtection"], mdrManaged=True),
             endpoint("e4", ["endpointProtection"], mdrManaged=None)]
    out = run(name, items)
    assert counters(out)["MDR"] == 2
    assert counters(out)[XDR_KEY] == 1
    assert out["transformedResponse"]["MDR"] == 50
    assert out["transformedResponse"]["isMDREnabled"] is True


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("body", [{}, {"items": []}, {"error": "Unauthorized"}])
def test_empty_or_error_read_is_never_mdr(name, body):
    spec = importlib.util.spec_from_file_location("sophos_" + name[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.transform(body)["transformedResponse"]
    assert result.get("isMDREnabled") is not True
