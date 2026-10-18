"""epp_transform emits isEPPMisconfigured (2 Oct 2026). Its RTA entry reads this file via the isEPPConfigured
method, but nothing emitted the key. Inverted key: True is the insecure condition, so an empty, missing or
error read must never read False (a pass). Sample endpoints follow the Sophos /endpoint/v1/endpoints shape."""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).parent
FRESH = (datetime.utcnow() - timedelta(hours=1)).isoformat()[:19] + "Z"
STALE = "2020-01-01T00:00:00Z"


def run(body):
    spec = importlib.util.spec_from_file_location("sophos_mdr_epp", HERE / "epp_transform.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)["transformedResponse"]


@pytest.mark.parametrize("body", [{}, [], {"items": []}, {"error": "Unauthorized"}, "{}", {"data": [], "validation": {"status": "unknown", "errors": [], "warnings": []}}],
                         ids=lambda b: json.dumps(b)[:30])
def test_empty_or_error_read_is_never_a_pass(body):
    assert run(body).get("isEPPMisconfigured") is not False


def endpoint(products):
    return {"id": "e1", "type": "computer", "lastSeenAt": FRESH,
            "assignedProducts": [{"code": c, "status": "installed"} for c in products],
            "health": {"services": {"serviceDetails": []}}}


def test_protected_endpoint_is_not_misconfigured():
    tr = run({"items": [endpoint(["endpointProtection", "interceptX"])]})
    assert tr["isEPPConfigured"] is True
    assert tr["isEPPMisconfigured"] is False


def test_unprotected_endpoint_is_misconfigured():
    tr = run({"items": [endpoint(["xdr"])]})
    assert tr["isEPPMisconfigured"] is True


@pytest.mark.parametrize("products", [["endpointProtection", "interceptX"], ["xdr"], []])
def test_a_fleet_whose_every_endpoint_is_stale_is_misconfigured_never_none(products):
    """Every endpoint older than the active window leaves no protected endpoint: configured False, misconfigured True.
    None would travel with a success status and be graded as a failure, so the measured negative carries a value."""
    old = dict(endpoint(products), lastSeenAt=STALE)
    out = {"items": [old]}
    spec = importlib.util.spec_from_file_location("sophos_mdr_epp_dark", HERE / "epp_transform.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.transform(out)
    tr = result["transformedResponse"]
    assert tr["isEPPConfigured"] is False
    assert tr["isEPPMisconfigured"] is True
    assert tr["staleEndpointCount"] == 1
    assert [key for key, value in tr.items() if value is None] == []
    assert result["additionalInfo"]["dataCollection"]["status"] == "success"
