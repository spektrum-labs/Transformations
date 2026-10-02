"""isZeroStandingPrivilegesEnabled fails closed (2 Oct 2026).

The core-key live verification found it returned True (a pass) on [] and {"data": []}: an empty profile
list was read as "vacuously true". An empty, missing or error reply, or a list with no active profile, now
reads None with the reason in dataCollection.errors (Unevaluated). A real profile list still measures.

Samples follow Britive's documented GET /api/apps/{appId}/paps profile objects (papId, name, status,
expirationDuration in milliseconds, 0 = no expiry), merged by the integration as {"profiles": [...]}. Raw
vendor bodies are not readable from the evidence store (403), so these are the documented shapes.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent
KEY = "isZeroStandingPrivilegesEnabled"


def run(body):
    spec = importlib.util.spec_from_file_location("britive_zsp", HERE / "iszerostandingprivilegesenabled.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


EMPTY_OR_ERROR = [
    {},
    [],
    None,
    "",
    "{}",
    "[]",
    "not json",
    {"data": []},
    {"profiles": []},
    {"paps": []},
    {"value": []},
    {"items": []},
    {"data": [], "validation": {"status": "unknown", "errors": [], "warnings": []}},
    {"data": {"profiles": [{"status": "active"}]}, "validation": {"status": "failed", "errors": ["x"], "warnings": []}},
    {"error": "Unauthorized", "statusCode": 401},
    {"message": "Invalid token"},
    {"profiles": [{"papId": "p1", "name": "Admin", "status": "inactive", "expirationDuration": 0}]},
    {"profiles": "not a list"},
    {"profiles": [None, "x"]},
]


@pytest.mark.parametrize("body", EMPTY_OR_ERROR, ids=lambda b: json.dumps(b, default=str)[:40])
def test_empty_missing_or_error_reply_is_unevaluated_with_a_reason(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])


def profiles(*durations):
    return {"profiles": [{"papId": "p" + str(i), "name": "Profile " + str(i), "status": "active",
                          "expirationDuration": d} for i, d in enumerate(durations)]}


def test_every_active_profile_with_an_expiry_passes():
    out = run(profiles(3600000, 900000))
    assert out["transformedResponse"][KEY] is True
    assert out["transformedResponse"]["activeProfiles"] == 2
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_an_active_profile_without_expiry_fails():
    out = run(profiles(3600000, 0))
    assert out["transformedResponse"][KEY] is False
    assert out["transformedResponse"]["profilesWithoutExpiry"] == ["Profile 1"]
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_engine_envelope_and_json_string_measure():
    body = {"data": profiles(3600000), "validation": {"status": "valid", "errors": [], "warnings": []}}
    assert run(body)["transformedResponse"][KEY] is True
    assert run(json.dumps(profiles(0)))["transformedResponse"][KEY] is False
