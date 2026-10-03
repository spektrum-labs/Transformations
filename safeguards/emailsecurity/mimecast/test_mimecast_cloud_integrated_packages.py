"""Mimecast Email Security Cloud Integrated getAccount package keys: licensed package -> True,
account without it -> False, anything that is not a getAccount account -> None."""
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

KEYS = {
    "isAttachmentSandboxDetonationEnabled": "Attachment Protection (Site) [1056]",
    "isImposterEmailDetectionEnabled": "Impersonation Protection [1060]",
    "isClickTimeURLRewriteEnabled": "URL Protection (Site) [1043]",
    "isMaliciousClickBlockingEnabled": "URL Protection (Site) [1043]",
    "isPostDeliveryQuarantineEnabled": "Threat Remediation [1075]",
    "isEmailTraceabilityEnabled": "Metadata Track and Trace (Site) [1032]",
}
BASE = ["Mimecast Platform [1033]", "Branding [1003]", "[Email Security - Cloud Integrated] [ES_130]"]


def load(key):
    spec = importlib.util.spec_from_file_location("mimecast_ci_" + key, os.path.join(HERE, key + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def body(packages, meta_status=200, fail=None):
    raw = {"meta": {"status": meta_status}, "fail": fail or [],
           "data": [{"accountCode": "CUSA00A00", "accountName": "Example", "packages": packages}]}
    return {"data": raw, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def value(key, payload):
    return load(key)(payload)["transformedResponse"][key]


@pytest.mark.parametrize("key,package", sorted(KEYS.items()))
def test_licensed_package_is_true(key, package):
    out = load(key)(body(BASE + [package]))["transformedResponse"]
    assert out[key] is True
    assert out["licensedPackageCount"] == len(BASE) + 1


@pytest.mark.parametrize("key", sorted(KEYS))
def test_account_without_package_is_false(key):
    assert value(key, body(BASE)) is False
    assert value(key, body([])) is False


@pytest.mark.parametrize("key", sorted(KEYS))
def test_string_and_bare_bodies(key):
    raw = body(BASE + [KEYS[key]])["data"]
    assert value(key, raw) is True
    assert value(key, json.dumps(raw)) is True


@pytest.mark.parametrize("key", sorted(KEYS))
@pytest.mark.parametrize("payload", [
    None, {}, [], "",
    {"data": []},
    {"data": [{"accountName": "no packages field"}]},
    {"meta": {"status": 401}, "data": [], "fail": [{"errors": [{"code": "unauthorized"}]}]},
    {"error": True, "message": "401 Unauthorized"},
    {"foo": {"bar": 1}},
])
def test_no_evidence_is_none(key, payload):
    assert value(key, payload) is None


@pytest.mark.parametrize("key", sorted(KEYS))
def test_fail_entry_or_bad_meta_is_none(key):
    assert value(key, body(BASE + [KEYS[key]], fail=[{"key": "x", "errors": [{"code": "err"}]}])) is None
    assert value(key, body(BASE + [KEYS[key]], meta_status=403)) is None
