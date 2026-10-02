"""Tenable ASM inventory counts fail closed (2 Oct 2026).

The core-key live verification found exposedAdminPortsCount and exposedSecretKeysCount returned 0 (a pass on
"count == 0") from {}, [], null and error bodies. Every inventory count shares the same run_criterion, so all
twelve had the defect. An empty, missing or error reply, a validation failure, an exception, or a zero on a
partial inventory now reads None with the reason in dataCollection.errors (Unevaluated). A real inventory
still measures, including a real zero.

Samples follow the documented POST /api/1.0/inventory envelope ({"total", "stats", "assets": [...]}, asset
fields named by the getInventory columns in the integration definition). Raw vendor bodies are not readable
from the evidence store (403), so these are the documented shapes, not captured bodies.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent

COUNTS = {
    "assetsonblocklistcount": "assetsOnBlocklistCount",
    "assetswithknowncvescount": "assetsWithKnownCvesCount",
    "assettriagebacklogcount": "assetTriageBacklogCount",
    "certificateexpiringsooncount": "certificateExpiringSoonCount",
    "domainexpiringsooncount": "domainExpiringSoonCount",
    "expiredcertificatecount": "expiredCertificateCount",
    "exposedadminportscount": "exposedAdminPortsCount",
    "exposedloginpagescount": "exposedLoginPagesCount",
    "exposedsecretkeyscount": "exposedSecretKeysCount",
    "mixedcontentassetscount": "mixedContentAssetsCount",
    "sslerrorcount": "sslErrorCount",
    "vulnerablewordpresscount": "vulnerableWordPressCount",
}


def load(name):
    spec = importlib.util.spec_from_file_location("tasm_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def key_of(name, response):
    keys = [k for k in response["transformedResponse"] if k.lower() == name]
    assert keys, name
    return keys[0]


EMPTY_OR_ERROR = [
    {},
    [],
    None,
    "",
    "{}",
    "not json",
    {"value": []},
    {"data": []},
    {"items": []},
    {"results": []},
    {"resources": []},
    {"assets": []},
    {"total": 0, "stats": {}, "assets": []},
    {"data": {"assets": []}, "validation": {"status": "unknown", "errors": [], "warnings": []}},
    {"data": {"assets": [{"id": "a"}]}, "validation": {"status": "failed", "errors": ["schema"], "warnings": []}},
    {"error": "Unauthorized", "statusCode": 401},
    {"message": "Invalid API key"},
    {"assets": "not a list"},
]


@pytest.mark.parametrize("name", list(COUNTS))
@pytest.mark.parametrize("body", EMPTY_OR_ERROR, ids=lambda b: json.dumps(b, default=str)[:40])
def test_empty_missing_or_error_reply_is_unevaluated_with_a_reason(name, body):
    out = load(name)(body)
    assert out["transformedResponse"][COUNTS[name]] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])


def clean_asset(host):
    return {"id": host, "bd.original_hostname": host, "bd.record_type": "A", "ports.ports": ["443"],
            "ports.cves": [], "ssl.valid_to": "2099-01-01T00:00:00Z", "ssl.sslerror": [],
            "wtech.secretkeys": [], "wtech.has_login": False, "wtech.mixedcontent": False,
            "wpscan.vulnerabilities": [], "rbls.rbls": [], "domaininfo.expiresdate": "2099-01-01T00:00:00Z",
            "bd.addedtoportfolio": "2020-01-01T00:00:00Z", "bd.tags": ["prod"]}


@pytest.mark.parametrize("name", list(COUNTS))
def test_a_real_clean_inventory_measures_zero(name):
    body = {"total": 2, "stats": {"hostcount": 2}, "assets": [clean_asset("a.example.com"), clean_asset("b.example.com")]}
    out = load(name)(body)
    assert out["transformedResponse"][COUNTS[name]] == 0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name", list(COUNTS))
def test_zero_on_a_partial_inventory_is_unevaluated(name):
    body = {"total": 50, "stats": {}, "assets": [clean_asset("a.example.com")]}
    out = load(name)(body)
    assert out["transformedResponse"][COUNTS[name]] is None
    assert "partial inventory" in out["additionalInfo"]["dataCollection"]["errors"][0]


def test_exposed_admin_port_is_counted():
    exposed = dict(clean_asset("db.example.com"), **{"ports.ports": ["443", "3389"]})
    body = {"total": 2, "assets": [clean_asset("a.example.com"), exposed]}
    out = load("exposedadminportscount")(body)
    assert out["transformedResponse"]["exposedAdminPortsCount"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_exposed_admin_port_on_a_partial_inventory_is_a_lower_bound():
    exposed = dict(clean_asset("db.example.com"), **{"ports.ports": ["22"]})
    out = load("exposedadminportscount")({"total": 40, "assets": [exposed]})
    assert out["transformedResponse"]["exposedAdminPortsCount"] == 1
    assert out["transformedResponse"]["partial"] is True


def test_exposed_secret_key_is_counted():
    leaking = dict(clean_asset("app.example.com"), **{"wtech.secretkeys": ["AWS Access Key"]})
    body = json.dumps({"total": 2, "assets": [clean_asset("a.example.com"), leaking]})
    out = load("exposedsecretkeyscount")(body)
    assert out["transformedResponse"]["exposedSecretKeysCount"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
