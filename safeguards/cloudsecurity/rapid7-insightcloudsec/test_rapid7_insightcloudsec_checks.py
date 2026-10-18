"""Rapid7 InsightCloudSec core checks, on bodies shaped like the vendor's published v2/v3 OpenAPI examples
(docs.rapid7.com/_api/insightcloudsec-v2-api.yaml, -v3-api.yaml). No customer body has been seen.
Fail closed: no data, an error or an incomplete read gives None plus dataCollection.status "error" (Unevaluated)."""
import datetime as dt
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("r7ics_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def out(name, body):
    res = load(name)(body)
    return res["transformedResponse"], res["additionalInfo"]["dataCollection"]["status"]


def ago(**kw):
    return (dt.datetime.utcnow() - dt.timedelta(**kw)).strftime("%Y-%m-%d %H:%M:%S")


def storage(records, total=None):
    return {"counts": {"storagecontainer": len(records) if total is None else total, "instance": 4},
            "selected_resource_type": "storagecontainer", "next_cursor": None,
            "resources": [{"resource_type": "storagecontainer", "storagecontainer": r} for r in records]}


def scorecard(rows, row_total=None, col_pages=1):
    return {"page_data": {"row": {"total_pages": 1, "page": 1, "page_size": 20,
                                  "total_count": len(rows) if row_total is None else row_total},
                          "column": {"total_pages": col_pages, "page": 1, "page_size": 100, "total_count": 2}},
            "data": {"scorecard": rows, "resource_scope_type": "divvyorganizationservice"}}


def row(sev, cells, custom=None):
    return {"id": "backoffice:1", "name": "x", "severity": sev, "custom_severity": custom,
            "series": [{"id": i, "impacted_resources": imp, "exempt_resources": 0, "total_resources": tot}
                       for i, (imp, tot) in enumerate(cells)]}


KEYS = {"ispublicstoragebucketexposed": "isPublicStorageBucketExposed",
        "unencryptedstorageresourcecount": "unencryptedStorageResourceCount",
        "compliancepercentage": "compliancePercentage",
        "criticalopenfindingscount": "criticalOpenFindingsCount",
        "isscheduledscanningenabled": "isScheduledScanningEnabled",
        "isiacmisconfigscanningenabled": "isIaCMisconfigScanningEnabled"}

NO_DATA = [{}, None, "", "{}", {"error": True, "statusCode": 401}, {"status": "Error", "message": "403"},
           {"status_code": 403, "_response_data": {"detail": "forbidden"}}, {"hello": "world"},
           {"apiResponse": {"clouds": "nope"}}, {"data": None, "validation": {"status": "unknown"}}]


@pytest.mark.parametrize("body", NO_DATA)
@pytest.mark.parametrize("name", sorted(KEYS))
def test_no_data_is_unevaluated(name, body):
    value, status = out(name, body)
    assert value[KEYS[name]] is None
    assert status == "error"


def test_public_storage():
    ok = storage([{"public": False, "global_encryption": "AES256"}, {"public": False, "global_encryption": "aws:kms"}])
    bad = storage([{"public": True, "global_encryption": None}, {"public": False, "global_encryption": "AES256"}])
    assert out("ispublicstoragebucketexposed", ok) == ({"isPublicStorageBucketExposed": False, "publicStorageContainerCount": 0, "storageContainerCount": 2}, "success")
    assert out("ispublicstoragebucketexposed", bad)[0]["isPublicStorageBucketExposed"] is True
    # wrapped in the IS envelope and the new TS input format
    assert out("ispublicstoragebucketexposed", {"data": {"apiResponse": bad}, "validation": {}})[0]["isPublicStorageBucketExposed"] is True
    # incomplete paging, a missing field, a non-boolean value: Unevaluated
    for body in [storage([{"public": False}], total=5), storage([{"name": "b"}]), storage([{"public": "yes"}])]:
        assert out("ispublicstoragebucketexposed", body) [0]["isPublicStorageBucketExposed"] is None
    # zero storage containers, with the server's own count of zero, is a measurement
    assert out("ispublicstoragebucketexposed", storage([]))[0]["isPublicStorageBucketExposed"] is False


def test_unencrypted_storage():
    body = storage([{"public": False, "global_encryption": v} for v in ["AES256", None, "", "None", False, "aws:kms", True]])
    assert out("unencryptedstorageresourcecount", body)[0]["unencryptedStorageResourceCount"] == 4
    assert out("unencryptedstorageresourcecount", storage([{"global_encryption": "AES256"}]))[0]["unencryptedStorageResourceCount"] == 0
    assert out("unencryptedstorageresourcecount", storage([{"public": False}]))[0]["unencryptedStorageResourceCount"] is None
    assert out("unencryptedstorageresourcecount", storage([{"global_encryption": "AES256"}], total=3))[0]["unencryptedStorageResourceCount"] is None


def test_compliance_and_critical():
    body = scorecard([row(5, [(3, 21), (0, 17)]), row(2, [(0, 10), (0, 0)]), row(4, [(1, 5), (0, 5)], custom=5)])
    value, status = out("compliancepercentage", body)
    assert status == "success" and value["compliancePercentage"] == 60.0 and value["totalChecks"] == 5
    assert out("criticalopenfindingscount", body)[0]["criticalOpenFindingsCount"] == 4
    clean = scorecard([row(5, [(0, 21)]), row(3, [(0, 4)])])
    assert out("compliancepercentage", clean)[0]["compliancePercentage"] == 100.0
    assert out("criticalopenfindingscount", clean)[0]["criticalOpenFindingsCount"] == 0
    for bad in [scorecard([row(5, [(0, 1)])], row_total=7), scorecard([row(5, [(0, 1)])], col_pages=3),
                scorecard([{"id": "x", "severity": 5, "series": [{"impacted_resources": 1}]}])]:
        assert out("compliancepercentage", bad)[0]["compliancePercentage"] is None
        assert out("criticalopenfindingscount", bad)[0]["criticalOpenFindingsCount"] is None
    # nothing in scope is not 0% or 100%
    assert out("compliancepercentage", scorecard([row(3, [(0, 0)])]))[0]["compliancePercentage"] is None
    assert out("criticalopenfindingscount", scorecard([{"id": "x", "series": []}]))[0]["criticalOpenFindingsCount"] is None


def test_scheduled_scanning():
    fresh = {"clouds": [{"id": 1, "name": "a", "status": "DEFAULT", "last_refreshed": ago(hours=2)},
                        {"id": 2, "name": "b", "status": "DEFAULT", "last_refreshed": ago(hours=30)}]}
    assert out("isscheduledscanningenabled", fresh)[0]["isScheduledScanningEnabled"] is True
    paused = {"clouds": [{"id": 1, "name": "a", "status": "PAUSED", "last_refreshed": ago(hours=1)}]}
    stale = {"clouds": [{"id": 1, "name": "a", "status": "DEFAULT", "last_refreshed": ago(days=5)},
                        {"id": 2, "name": "b", "status": "DEFAULT", "last_refreshed": ago(hours=1)}]}
    never = {"clouds": [{"id": 1, "name": "a", "status": "DEFAULT", "last_refreshed": None}]}
    for body in [paused, stale, never, {"clouds": []}]:
        assert out("isscheduledscanningenabled", body)[0]["isScheduledScanningEnabled"] is False
    assert out("isscheduledscanningenabled", {"clouds": [{"id": 1, "name": "a"}]})[0]["isScheduledScanningEnabled"] is None


def test_iac_scanning():
    def scans(times, total=None, pages=1):
        return {"page": 1, "total_pages": pages, "total_count": len(times) if total is None else total,
                "data": [{"id": i, "status": "success", "create_time": t} for i, t in enumerate(times)]}
    iso = lambda **kw: (dt.datetime.utcnow() - dt.timedelta(**kw)).isoformat()
    assert out("isiacmisconfigscanningenabled", scans([iso(days=90), iso(days=3)]))[0]["isIaCMisconfigScanningEnabled"] is True
    assert out("isiacmisconfigscanningenabled", scans([iso(days=90)]))[0]["isIaCMisconfigScanningEnabled"] is False
    assert out("isiacmisconfigscanningenabled", scans([]))[0]["isIaCMisconfigScanningEnabled"] is False
    # part of the list read, none recent: the newest may be unread
    assert out("isiacmisconfigscanningenabled", scans([iso(days=90)], total=40, pages=2))[0]["isIaCMisconfigScanningEnabled"] is None
    # recent scan on a partial page is still proof
    assert out("isiacmisconfigscanningenabled", scans([iso(days=1)], total=40, pages=2))[0]["isIaCMisconfigScanningEnabled"] is True
