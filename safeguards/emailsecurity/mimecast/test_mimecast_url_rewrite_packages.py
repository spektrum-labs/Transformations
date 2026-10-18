"""Mimecast isURLRewriteEnabled now reads the getAccount package list: the URL Protection package
([1043]) licensed -> True, an account without it -> False, anything that is not a getAccount account
(an error, a fail entry, an unrelated body) -> None (not measured, shown "Not evaluated").

The managed-URL list shape is still graded the old way until the stored definition points this key at
getAccount; the last tests pin that transitional branch. All payloads here are synthetic."""
import copy
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("mimecast_isurlrewriteenabled", os.path.join(HERE, "isurlrewriteenabled.py"))
MOD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MOD)

KEY = "isURLRewriteEnabled"
BASE = ["Mimecast Platform [1033]", "Branding [1003]", "Enhanced Logging [1061]"]
URL_PROTECTION = "URL Protection (Site) [1043]"
VALIDATION = {"status": "skipped", "errors": [], "warnings": []}


def account(packages):
    return {"accountCode": "EXAMPLE00A00", "accountName": "Example Co", "packages": packages}


def full_body(packages, meta_status=200, fail=None):
    return {"meta": {"status": meta_status}, "fail": fail or [], "data": [account(packages)]}


def enveloped(packages):
    return {"data": full_body(packages), "validation": VALIDATION}


def run(payload):
    out = MOD.transform(payload)
    return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]


def test_licensed_package_is_true_in_every_shape():
    packages = BASE + [URL_PROTECTION]
    assert run(enveloped(packages)) == (True, "success")
    assert run(full_body(packages)) == (True, "success")
    assert run(json.dumps(full_body(packages))) == (True, "success")
    assert run([account(packages)]) == (True, "success")  # Token-Service may hand the bare list
    assert run(account(packages)) == (True, "success")  # or a lone account


def test_matched_by_product_id_not_by_name():
    assert run(enveloped(BASE + ["URL Protection Renamed [1043]"])) == (True, "success")


def test_flipped_package_removed_is_false():
    packages = BASE + [URL_PROTECTION]
    assert run(enveloped(packages)) == (True, "success")
    flipped = copy.deepcopy(packages)
    flipped.remove(URL_PROTECTION)
    assert run(enveloped(flipped)) == (False, "success")
    assert run(enveloped([])) == (False, "success")


def test_similar_ids_do_not_match():
    assert run(enveloped(BASE + ["Something Else [10430]", "Other [1044]"])) == (False, "success")


def test_error_bodies_are_not_measured():
    forbidden = {"meta": {"status": 403}, "fail": [{"errors": [{"code": "err_xdk_forbidden", "message": "x"}]}], "data": []}
    assert run({"data": forbidden, "validation": VALIDATION}) == (None, "error")
    assert run(forbidden) == (None, "error")
    assert run({"error": True, "message": "HTTP 403: Forbidden"}) == (None, "error")
    assert run(full_body(BASE + [URL_PROTECTION], meta_status=500)) == (None, "error")


def test_unrelated_or_empty_bodies_are_not_measured():
    for body in (None, {}, "{}", [], {"data": []}, {"hello": "world"}, "not json", {"data": [{"accountCode": "X"}]}):
        assert run(body) == (None, "error"), body


def test_not_measured_carries_no_false_verdict():
    out = MOD.transform({"error": True, "message": "boom"})
    assert out["transformedResponse"] == {KEY: None}
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


# Transitional branch: the managed-URL list the old definition still hands over.
def test_legacy_managed_url_list_is_graded_as_before_until_the_definition_moves():
    entries = [{"domain": "example.com", "disableRewrite": False}, {"domain": "example.org", "disableRewrite": True}]
    assert run({"meta": {"pagination": {"totalCount": 2}}, "fail": [], "data": entries}) == (True, "success")
    assert run(entries) == (True, "success")
    assert run({"meta": {"pagination": {"totalCount": 0}}, "fail": [], "data": []}) == (False, "success")


def test_legacy_error_is_still_not_measured():
    assert run({"meta": {"status": 403}, "fail": [{"errors": [{"code": "app_forbidden"}]}], "data": []}) == (None, "error")
