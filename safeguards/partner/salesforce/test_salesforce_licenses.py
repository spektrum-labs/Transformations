"""Salesforce licence transforms: real values on complete query results, None otherwise."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("sf_lic_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def query(sobject, records, done=True, total=None):
    recs = [dict(r, attributes={"type": sobject}) for r in records]
    inner = {"size": len(recs), "totalSize": len(recs) if total is None else total, "done": done, "records": recs}
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def run(key, payload):
    return load(key)(payload)


def value(key, payload):
    return run(key, payload)["transformedResponse"][key]


def not_evaluated(key, payload):
    out = run(key, payload)
    return out["transformedResponse"][key] is None and out["additionalInfo"]["dataCollection"]["status"] == "error"


def lic(status="Active", total=25, used=10, name="Salesforce"):
    return {"Id": "1001", "Name": name, "Status": status, "TotalLicenses": total, "UsedLicenses": used}


def pkg(status="Active", ns="acme"):
    return {"Id": "0501", "NamespacePrefix": ns, "Status": status, "ExpirationDate": None, "AllowedLicenses": 10, "UsedLicenses": 2}


KEY_LIC = "confirmedLicensePurchased"
KEY_PKG = "expiredPackageLicensesCount"


def test_an_active_licence_with_seats_is_purchased():
    out = run(KEY_LIC, query("UserLicense", [lic("Disabled", 5), lic("Active", 25)]))
    assert out["transformedResponse"][KEY_LIC] is True
    assert out["transformedResponse"]["activeSeats"] == 25


def test_licences_that_are_all_disabled_or_empty_are_not_purchased():
    assert value(KEY_LIC, query("UserLicense", [lic("Disabled", 5)])) is False
    assert value(KEY_LIC, query("UserLicense", [lic("Active", 0)])) is False
    assert value(KEY_LIC, query("UserLicense", [lic("Active", None)])) is False
    assert value(KEY_LIC, query("UserLicense", [lic("Active", "25")])) is False


def test_flipping_the_status_flips_the_licence():
    assert value(KEY_LIC, query("UserLicense", [lic("Active")])) is True
    assert value(KEY_LIC, query("UserLicense", [lic("Disabled")])) is False


def test_no_licence_record_is_not_measured():
    assert not_evaluated(KEY_LIC, query("UserLicense", []))


def test_expired_packages_are_counted():
    out = run(KEY_PKG, query("PackageLicense", [pkg("Active", "a"), pkg("Expired", "b"), pkg("expired", "c"), pkg("Trial", "d")]))
    assert out["transformedResponse"][KEY_PKG] == 2
    assert out["transformedResponse"]["expiredPackages"] == ["b", "c"]


def test_no_expired_package_is_zero_and_no_package_is_zero():
    assert value(KEY_PKG, query("PackageLicense", [pkg("Active"), pkg("Free")])) == 0
    assert value(KEY_PKG, query("PackageLicense", [])) == 0


def test_a_missing_status_is_never_scored_beside_a_count():
    assert not_evaluated(KEY_PKG, query("PackageLicense", [pkg("Active"), {"Id": "x", "NamespacePrefix": "n"}]))
    # one Expired plus a missing Status is only "at least 1": an inclusive lessThan would pass on it
    assert not_evaluated(KEY_PKG, query("PackageLicense", [pkg("Expired"), {"Id": "x"}]))
    assert value(KEY_PKG, query("PackageLicense", [pkg("Expired"), pkg("Active")])) == 1


@pytest.mark.parametrize("key,sobject,rec", [(KEY_LIC, "UserLicense", lic()), (KEY_PKG, "PackageLicense", pkg("Expired"))])
def test_partial_read_is_not_scored(key, sobject, rec):
    assert not_evaluated(key, query(sobject, [rec], done=False))
    assert not_evaluated(key, query(sobject, [rec], total=5))


@pytest.mark.parametrize("key,wrong", [(KEY_LIC, "PackageLicense"), (KEY_PKG, "UserLicense")])
def test_the_wrong_object_is_not_scored(key, wrong):
    assert not_evaluated(key, query(wrong, [lic("Active")]))


NO_EVIDENCE = [
    None, {}, [], "", "{}",
    {"errors": ["Unauthorized"]},
    {"error": "invalid_client", "status_code": 400},
    [{"errorCode": "INVALID_SESSION_ID", "message": "Session expired or invalid"}],
    {"statusCode": 403, "error": "Forbidden"},
    {"data": {"apiResponse": {"status_code": 500, "message": "boom"}}, "validation": {}},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
    {"data": {"apiResponse": {"records": ["a"], "totalSize": 1, "done": True}}, "validation": {}},
]


@pytest.mark.parametrize("key", [KEY_LIC, KEY_PKG])
@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(key, payload):
    assert not_evaluated(key, payload)
