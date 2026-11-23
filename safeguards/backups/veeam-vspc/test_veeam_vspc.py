"""Veeam Service Provider Console (REST API v3) transforms: real verdicts on complete reads, None otherwise.

Bodies follow the VSPC v3 collection shape from the published OpenAPI spec (vspc_rest_80.yaml):
{"meta": {"pagingInfo": {"total", "count", "offset"}}, "data": [...], "errors": null}.
Each judged check reads a company-scoped workflow ({"company": ..., "jobs" | "backupServers" | ...});
test_veeam_vspc_one_company.py covers the one-company scoping itself.
"""
import importlib.util
import os
from datetime import datetime, timedelta, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("veeam_vspc_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def coll(items, total=None):
    n = len(items) if total is None else total
    return {"meta": {"pagingInfo": {"total": n, "count": len(items), "offset": 0}}, "data": items, "errors": None}


def ts_wrap(body):
    """How Token-Service hands an IS response to a transform."""
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def value(name, key, payload):
    return load(name)(payload)["transformedResponse"][key]


def stamp(days_ago):
    t = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return t.strftime("%Y-%m-%d %H:%M:%S.000000+00:00")


COMPANY = "0a0a0a0a-1b1b-4c2c-8d3d-4e4e4e4e4e4e"


def job(name, jtype="BackupVm", enabled=True, schedule="Daily", status="Success", last=None):
    return {"instanceUid": name + "-uid", "name": name, "backupServerUid": "srv-1", "organizationUid": COMPANY,
            "type": jtype, "isEnabled": enabled, "scheduleType": schedule, "status": status,
            "lastRun": last or stamp(1), "lastEndTime": last or stamp(1)}


def company():
    return coll([{"instanceUid": COMPANY}])


def servers(*uids):
    return coll([{"instanceUid": u, "organizationUid": COMPANY} for u in (uids or ("srv-1", "srv-2"))])


CONFIGURED = {"companyUid": COMPANY}


def jobs_body(items, total=None):
    """The getCompanyJobs workflow body."""
    return {"configuredSettings": CONFIGURED, "company": company(), "jobs": coll(items, total)}


def lic_body(items):
    """The getCompanyLicenses workflow body."""
    return {"configuredSettings": CONFIGURED, "company": company(), "backupServers": servers(),
            "licenses": coll(items)}


NO_EVIDENCE = [
    {}, "", None,
    {"status": 401, "message": "Unauthorized"},
    {"error": {"code": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"meta": {"page": 1}, "links": {}},
    {"meta": None, "data": None, "errors": [{"message": "Access denied", "type": "security", "code": 1100}]},
    {"data": []},
]

SIMPLE = [
    ("isbackupenabled", "isBackupEnabled"),
    ("isbackuptypesscheduled", "isBackupTypesScheduled"),
    ("isbackuptested", "isBackupTested"),
    ("confirmedlicensepurchased", "confirmedLicensePurchased"),
    ("isbackupimmutable", "isBackupImmutable"),
]


@pytest.mark.parametrize("name,key", SIMPLE)
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_measured(name, key, body):
    assert value(name, key, body) is None


@pytest.mark.parametrize("name,key", SIMPLE[:3])
def test_partial_read_is_not_measured(name, key):
    assert value(name, key, jobs_body([job("a")], total=600)) is None


def test_backup_enabled():
    assert value("isbackupenabled", "isBackupEnabled",
                 ts_wrap(jobs_body([job("a"), job("r", "ReplicationVM")]))) is True
    assert value("isbackupenabled", "isBackupEnabled", jobs_body([job("a", enabled=False)])) is False
    assert value("isbackupenabled", "isBackupEnabled", jobs_body([job("r", "ReplicationVM")])) is False
    # An empty job list proves nothing about the company (and the filter is unproven): not evaluated.
    assert value("isbackupenabled", "isBackupEnabled", jobs_body([])) is None


def test_backup_types_scheduled():
    key = "isBackupTypesScheduled"
    assert value("isbackuptypesscheduled", key, jobs_body([job("a"), job("b", schedule="Chained")])) is True
    assert value("isbackuptypesscheduled", key, jobs_body([job("a"), job("b", schedule="NotScheduled")])) is False
    assert value("isbackuptypesscheduled", key, jobs_body([job("a", enabled=False)])) is False
    # disabled unscheduled jobs do not count against the enabled ones
    assert value("isbackuptypesscheduled", key,
                 jobs_body([job("a"), job("b", enabled=False, schedule="NotScheduled")])) is True


def test_backup_tested():
    key = "isBackupTested"
    assert value("isbackuptested", key, jobs_body([job("a"), job("sb", "SureBackup")])) is True
    assert value("isbackuptested", key, jobs_body([job("a"), job("sb", "SureBackup", status="Failed")])) is False
    assert value("isbackuptested", key, jobs_body([job("a"), job("sb", "SureBackup", last=stamp(120))])) is False
    assert value("isbackuptested", key, jobs_body([job("a"), job("sb", "SureBackup", enabled=False)])) is False
    assert value("isbackuptested", key, jobs_body([job("a")])) is False


def test_vspc_offset_timestamps_are_read():
    t = load("isbackuptested")
    late = (datetime.now(timezone.utc) - timedelta(days=89)).strftime("%Y-%m-%d %H:%M:%S.317000+02:00")
    assert t(jobs_body([job("sb", "SureBackup", last=late)]))["transformedResponse"]["isBackupTested"] is True


def lic(ltype="Rental", status="Valid", server="srv-1"):
    return {"backupServerUid": server, "type": ltype, "status": status, "edition": "Enterprise Plus"}


def test_license():
    key = "confirmedLicensePurchased"
    assert value("confirmedlicensepurchased", key, lic_body([lic(), lic("Perpetual", "Warning", "srv-2")])) is True
    assert value("confirmedlicensepurchased", key, lic_body([lic(), lic("Evaluation", server="srv-2")])) is False
    assert value("confirmedlicensepurchased", key, lic_body([lic("NFR")])) is False
    assert value("confirmedlicensepurchased", key, lic_body([lic(status="Expired")])) is False
    assert value("confirmedlicensepurchased", key, lic_body([])) is None


def vm_job(name, target, enabled=True, server="srv-1"):
    return {"instanceUid": name + "-uid", "targetRepositoryUid": target, "protectedVmCount": 3,
            "_embedded": {"backupServerJob": {"name": name, "backupServerUid": server, "organizationUid": COMPANY,
                                              "isEnabled": enabled, "type": "BackupVm"}}}


def repo(uid, immutable, rtype="LinuxHardened", parent=None, server="srv-1"):
    return {"instanceUid": uid, "name": "repo-" + uid, "backupServerUid": server, "type": rtype,
            "parentRepositoryUid": parent, "isImmutabilityEnabled": immutable}


def targets(jobs, repos):
    return ts_wrap({"configuredSettings": CONFIGURED, "company": company(), "backupServers": servers(),
                    "vmJobs": coll(jobs),
                    "repositories": coll(repos)})


def test_immutable():
    key = "isBackupImmutable"
    t = "isbackupimmutable"
    assert value(t, key, targets([vm_job("a", "r1")], [repo("r1", True), repo("r2", False)])) is True
    assert value(t, key, targets([vm_job("a", "r1"), vm_job("b", "r2")], [repo("r1", True), repo("r2", False)])) is False
    # A missing isImmutabilityEnabled is not a readable "no": not evaluated.
    assert value(t, key, targets([vm_job("a", "r1"), vm_job("b", "r2")], [repo("r1", True), repo("r2", None)])) is None
    sobr = [repo("s1", None, "ScaleOut"), repo("e1", True, parent="s1"), repo("e2", False, parent="s1")]
    assert value(t, key, targets([vm_job("a", "s1")], sobr)) is False
    sobr_ok = [repo("s1", None, "ScaleOut"), repo("e1", True, parent="s1"), repo("e2", True, parent="s1")]
    assert value(t, key, targets([vm_job("a", "s1")], sobr_ok)) is True


def test_immutable_not_measured():
    key = "isBackupImmutable"
    t = "isbackupimmutable"
    # target not in the list, same uid on another server, no enabled job, empty scale-out
    assert value(t, key, targets([vm_job("a", "r9")], [repo("r1", True)])) is None
    assert value(t, key, targets([vm_job("a", "r1")], [repo("r1", True, server="srv-2")])) is None
    assert value(t, key, targets([vm_job("a", "r1", server="srv-2")], [repo("r1", True)])) is None
    assert value(t, key, targets([vm_job("a", "r1", enabled=False)], [repo("r1", True)])) is None
    assert value(t, key, targets([vm_job("a", "s1")], [repo("s1", None, "ScaleOut")])) is None
    assert value(t, key, ts_wrap({"vmJobs": coll([vm_job("a", "r1")])})) is None


NOT_MEASURABLE = [
    ("isbackupencrypted", "isBackupEncrypted"),
    ("isbackuploggingenabled", "isBackupLoggingEnabled"),
    ("issamlenforced", "isSAMLEnforced"),
    ("isbackupenabledforcriticalsystems", "isBackupEnabledForCriticalSystems"),
]


@pytest.mark.parametrize("name,key", NOT_MEASURABLE)
@pytest.mark.parametrize("body", NO_EVIDENCE + [coll([job("a")]), coll([])])
def test_not_measurable_keys_never_give_a_verdict(name, key, body):
    out = load(name)(body)
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("name,key", NOT_MEASURABLE)
def test_not_measurable_reason_is_explicit_on_a_good_read(name, key):
    out = load(name)(ts_wrap(coll([job("a")])))
    assert "Not measurable through VSPC" in out["additionalInfo"]["dataCollection"]["errors"][0]


def enriched(raw):
    return {"data": raw, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def test_token_service_enriched_envelope_bare_and_wrapped():
    for raw in (jobs_body([job("a")]), {"apiResponse": jobs_body([job("a")])}):
        assert value("isbackupenabled", "isBackupEnabled", enriched(raw)) is True
    assert value("isbackupenabled", "isBackupEnabled", enriched(jobs_body([job("a", enabled=False)]))) is False
    assert value("isbackupenabled", "isBackupEnabled", enriched(None)) is None
    body = {"configuredSettings": CONFIGURED, "company": company(), "backupServers": servers(),
            "vmJobs": coll([vm_job("a", "r1")]),
            "repositories": coll([repo("r1", True)])}
    assert value("isbackupimmutable", "isBackupImmutable", enriched(body)) is True
    assert value("isbackupimmutable", "isBackupImmutable", enriched({"apiResponse": body})) is True


def test_every_file_opts_into_the_undrilled_input():
    for name in os.listdir(HERE):
        if name.endswith(".py") and not name.startswith("test_"):
            with open(os.path.join(HERE, name)) as fh:
                assert 'input.get("data")' in fh.read(), name
