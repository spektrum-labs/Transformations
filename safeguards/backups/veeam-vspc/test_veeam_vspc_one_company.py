"""Veeam Service Provider Console checks count only the configured company's own backups.

One VSPC console serves many companies. Integration-Service reads a company-scoped workflow:
"company" (the company the connection's Company UID names, from
GET /organizations/companies?filter=instanceUid equals <uid>), "backupServers" (that company's
Veeam Backup & Replication servers, filter organizationUid equals <uid>) and the data parts.
Each transform keeps only:

- jobs whose organizationUid is the company (BackupServerJob.organizationUid);
- VM jobs whose embedded backupServerJob.organizationUid is the company and whose server is the company's;
- repositories and licences whose backupServerUid is one of the company's backup servers.

The VSPC filter is a request-side narrowing that is UNPROVEN against a real console, so these
tests send whole-console bodies (the filter ignored) and expect each company to see only its own.

A missing company (no Company UID, so no company read), an ambiguous one, a missing backup
server set, or an error, empty or truncated read gives None (Not evaluated), never False and
never a verdict over the whole console. Synthetic data only.
"""
import copy
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

A = "1a1a1a1a-2b2b-4c3c-8d4d-5e5e5e5e5e5e"
B = "9f9f9f9f-8e8e-4d7d-9c6c-5b5b5b5b5b5b"
SRV_A = "aaaaaaaa-0000-4000-8000-00000000000a"
SRV_B = "bbbbbbbb-0000-4000-8000-00000000000b"


def load(name):
    spec = importlib.util.spec_from_file_location("veeam_vspc_oc_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def run(name, key, body):
    out = load(name)(body)
    return out["transformedResponse"][key], out


def value(name, key, body):
    return run(name, key, body)[0]


def coll(items, total=None):
    n = len(items) if total is None else total
    return {"meta": {"pagingInfo": {"total": n, "count": len(items), "offset": 0}}, "data": items, "errors": None}


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def job(name, org, server, jtype="BackupVm", enabled=True, schedule="Daily", status="Success"):
    return {"instanceUid": name + "-uid", "name": name, "backupServerUid": server, "organizationUid": org,
            "type": jtype, "isEnabled": enabled, "scheduleType": schedule, "status": status,
            "lastRun": "2099-01-01 00:00:00.000000+00:00", "lastEndTime": None}


def recent_job(name, org, server, **kw):
    from datetime import datetime, timedelta, timezone
    j = job(name, org, server, **kw)
    j["lastEndTime"] = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S.000000+00:00")
    return j


def server(uid, org):
    return {"instanceUid": uid, "name": "vbr-" + uid[:4], "organizationUid": org}


def lic(srv, ltype="Rental", status="Valid"):
    return {"backupServerUid": srv, "type": ltype, "status": status}


def vm_job(name, org, srv, target, enabled=True):
    return {"instanceUid": name + "-uid", "targetRepositoryUid": target, "protectedVmCount": 2,
            "_embedded": {"backupServerJob": {"name": name, "backupServerUid": srv, "organizationUid": org,
                                              "isEnabled": enabled, "type": "BackupVm"}}}


def repo(uid, srv, immutable, rtype="LinuxHardened"):
    return {"instanceUid": uid, "name": "repo-" + uid, "backupServerUid": srv, "type": rtype,
            "parentRepositoryUid": None, "isImmutabilityEnabled": immutable}


# ── one console, two companies. A is good everywhere, B is bad everywhere. ──
CONSOLE_JOBS = [
    recent_job("a-backup", A, SRV_A), recent_job("a-sure", A, SRV_A, jtype="SureBackup"),
    job("b-backup", B, SRV_B, enabled=False, schedule="NotScheduled"),
    job("b-sure", B, SRV_B, jtype="SureBackup", status="Failed"),
]
CONSOLE_SERVERS = [server(SRV_A, A), server(SRV_B, B)]
CONSOLE_LICENSES = [lic(SRV_A), lic(SRV_B, "Evaluation")]
CONSOLE_VM_JOBS = [vm_job("a-vm", A, SRV_A, "ra"), vm_job("b-vm", B, SRV_B, "rb")]
CONSOLE_REPOS = [repo("ra", SRV_A, True), repo("rb", SRV_B, False)]


def company(uid):
    return coll([{"instanceUid": uid}])


def conf(uid):
    """Integration-Service's echo of the connection's Company UID (output.echoSettings)."""
    return {"companyUid": uid}


def jobs_body(uid, jobs=None, filtered=False):
    jobs = CONSOLE_JOBS if jobs is None else jobs
    if filtered:
        jobs = [j for j in jobs if j["organizationUid"] == uid]
    return {"configuredSettings": conf(uid), "company": company(uid), "jobs": coll(jobs)}


def lic_body(uid, servers=None, licenses=None):
    return {"configuredSettings": conf(uid), "company": company(uid), "backupServers": coll(CONSOLE_SERVERS if servers is None else servers),
            "licenses": coll(CONSOLE_LICENSES if licenses is None else licenses)}


def targets_body(uid, servers=None, vm_jobs=None, repos=None):
    return {"configuredSettings": conf(uid), "company": company(uid), "backupServers": coll(CONSOLE_SERVERS if servers is None else servers),
            "vmJobs": coll(CONSOLE_VM_JOBS if vm_jobs is None else vm_jobs),
            "repositories": coll(CONSOLE_REPOS if repos is None else repos)}


JOB_CHECKS = [
    ("isbackupenabled", "isBackupEnabled"),
    ("isbackuptypesscheduled", "isBackupTypesScheduled"),
    ("isbackuptested", "isBackupTested"),
]
ALL = JOB_CHECKS + [("confirmedlicensepurchased", "confirmedLicensePurchased"),
                    ("isbackupimmutable", "isBackupImmutable")]


def body_for(name, uid):
    if name == "confirmedlicensepurchased":
        return lic_body(uid)
    if name == "isbackupimmutable":
        return targets_body(uid)
    return jobs_body(uid)


@pytest.mark.parametrize("name,key", ALL)
@pytest.mark.parametrize("wrap", [lambda b: b, ts_wrap, lambda b: {"data": b, "validation": {}}],
                         ids=["bare", "ts", "enriched"])
def test_each_company_sees_only_its_own(name, key, wrap):
    """The whole console comes back (filter ignored): A passes on A's data, B fails on B's."""
    assert value(name, key, wrap(body_for(name, A))) is True
    assert value(name, key, wrap(body_for(name, B))) is False


@pytest.mark.parametrize("name,key", JOB_CHECKS)
def test_filtered_and_unfiltered_reads_agree(name, key):
    assert value(name, key, jobs_body(A, filtered=True)) is value(name, key, jobs_body(A)) is True
    assert value(name, key, jobs_body(B, filtered=True)) is value(name, key, jobs_body(B)) is False


@pytest.mark.parametrize("name,key", JOB_CHECKS)
def test_another_companys_good_jobs_never_pass_this_company(name, key):
    # B has no jobs of its own; A's good jobs are on the console. B is not evaluated, never True.
    only_a = [j for j in CONSOLE_JOBS if j["organizationUid"] == A]
    assert value(name, key, jobs_body(B, jobs=only_a)) is None


def test_another_companys_licences_and_repositories_never_count():
    # B's console server lists no licence of B; A's valid licence must not pass B.
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(B, licenses=[lic(SRV_A)])) is None
    # A's evaluation licence on a server of B's must not fail A.
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, licenses=[lic(SRV_A), lic(SRV_B, "Evaluation")])) is True
    # B's mutable repository does not fail A; A's VM job is judged on A's repository only.
    assert value("isbackupimmutable", "isBackupImmutable", targets_body(A)) is True
    # A VM job owned by A but on B's server (inconsistent read) is not counted for A.
    assert value("isbackupimmutable", "isBackupImmutable",
                 targets_body(A, vm_jobs=[vm_job("x", A, SRV_B, "rb")])) is None


def test_backup_server_set_comes_from_the_company_not_the_console():
    # The console lists both servers; only A's counts for A, whatever the licences say.
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, servers=CONSOLE_SERVERS)) is True
    # A server another company owns is ignored even if it is in the backupServers part.
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, servers=[server(SRV_B, B)], licenses=[lic(SRV_B, "Evaluation")])) is None


@pytest.mark.parametrize("name,key", ALL)
def test_output_never_says_whether_the_console_held_other_companies(name, key):
    """No consoleFilterHonoured (or any other console-wide fact) in what a company sees."""
    for body in (body_for(name, A), body_for(name, B)):
        out = load(name)(body)
        assert "consoleFilterHonoured" not in out["transformedResponse"]
        assert "consoleFilterHonoured" not in str(out)
    text = str(run("isbackupenabled", "isBackupEnabled", jobs_body(A))[1])
    assert "b-backup" not in text and B not in text


# ── no company UID / no company read: Not evaluated ─────────────────────────

MISSING_UID = "Required integration credentials are not connected: companyUid"


def company_missing_bodies(name):
    full = body_for(name, A)
    no_company = {k: v for k, v in full.items() if k != "company"}
    return [
        # The definition before the Company UID: the old single-collection read.
        coll(CONSOLE_JOBS) if name in [n for n, _ in JOB_CHECKS] else (
            coll(CONSOLE_LICENSES) if name == "confirmedlicensepurchased" else
            {"vmJobs": coll(CONSOLE_VM_JOBS), "repositories": coll(CONSOLE_REPOS)}),
        # Integration-Service's answer when the setting is missing (the workflow stops at step 1).
        {"error": True, "errorType": "missing_credentials", "statusCode": 412, "status": "Error",
         "message": MISSING_UID, "missingFields": ["companyUid"]},
        no_company,
        dict(full, company=coll([])),                                       # no company matches
        dict(full, company=coll([{"instanceUid": A}, {"instanceUid": B}])),  # filter ignored: ambiguous
        dict(full, company=coll([{"instanceUid": "not-a-uid"}])),
        dict(full, company=coll([{"name": "no uid"}])),
        dict(full, company=coll([{"instanceUid": A}], total=2)),             # truncated
        dict(full, company={"errors": [{"message": "Access denied", "type": "security", "code": 1100}]}),
        dict(full, company=None),
    ]


@pytest.mark.parametrize("name,key", ALL)
def test_missing_company_is_not_evaluated(name, key):
    for i, body in enumerate(company_missing_bodies(name)):
        v, out = run(name, key, body)
        assert v is None, (i, out["additionalInfo"]["dataCollection"])
        assert out["additionalInfo"]["dataCollection"]["status"] == "error", i


@pytest.mark.parametrize("name,key", [("confirmedlicensepurchased", "confirmedLicensePurchased"),
                                      ("isbackupimmutable", "isBackupImmutable")])
def test_missing_backup_server_set_is_not_evaluated(name, key):
    full = body_for(name, A)
    for i, part in enumerate([
        "absent", coll([]), coll([server(SRV_B, B)]), coll([server(SRV_A, A)], total=3),
        {"errors": [{"message": "Forbidden", "type": "security", "code": 1100}]},
        {"error": True, "statusCode": 403, "status": "Error", "message": "forbidden"}, None, "",
    ]):
        body = {k: v for k, v in full.items() if k != "backupServers"} if part == "absent" else \
            dict(full, backupServers=part)
        assert value(name, key, body) is None, i


# ── error, empty or truncated data parts: Not evaluated ─────────────────────

BAD_PARTS = [
    "absent", None, "", {}, coll([]),
    {"meta": None, "data": None, "errors": [{"message": "Access denied", "type": "security", "code": 1100}]},
    {"error": True, "statusCode": 429, "status": "Error", "message": "rate limited"},
    {"data": []},
]


def with_part(body, key, part):
    if part == "absent":
        return {k: v for k, v in body.items() if k != key}
    return dict(body, **{key: part})


@pytest.mark.parametrize("name,key", JOB_CHECKS)
@pytest.mark.parametrize("part", BAD_PARTS + [coll(CONSOLE_JOBS[:1], total=900)])
def test_bad_job_read_is_not_evaluated(name, key, part):
    assert value(name, key, with_part(jobs_body(A), "jobs", part)) is None


@pytest.mark.parametrize("part", BAD_PARTS + [coll(CONSOLE_LICENSES[:1], total=900)])
def test_bad_licence_read_is_not_evaluated(part):
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 with_part(lic_body(A), "licenses", part)) is None


@pytest.mark.parametrize("which", ["vmJobs", "repositories"])
@pytest.mark.parametrize("part", BAD_PARTS)
def test_bad_target_read_is_not_evaluated(which, part):
    assert value("isbackupimmutable", "isBackupImmutable", with_part(targets_body(A), which, part)) is None


def test_company_uid_matches_case_insensitively():
    upper = {"configuredSettings": conf(A), "company": coll([{"instanceUid": A.upper()}]), "jobs": coll(CONSOLE_JOBS)}
    assert value("isbackupenabled", "isBackupEnabled", upper) is True


# ── the returned company must be the configured one ─────────────────────────

@pytest.mark.parametrize("name,key", ALL)
def test_returned_company_must_match_the_configured_uid(name, key):
    """A console that ignores the instanceUid filter and holds one company answers with that company
    whatever UID was asked for. The echoed Company UID must match it, or nothing is evaluated."""
    good = body_for(name, A)
    assert value(name, key, good) is True                      # a match is unchanged
    wrong = dict(good, configuredSettings=conf(B))             # asked for B, console answered A
    v, out = run(name, key, wrong)
    assert v is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "does not match" in out["additionalInfo"]["dataCollection"]["errors"][0]
    # Case does not matter.
    assert value(name, key, dict(good, configuredSettings=conf(A.upper()))) is True


@pytest.mark.parametrize("name,key", ALL)
@pytest.mark.parametrize("configured", ["absent", None, {}, {"companyUid": ""}, {"companyUid": "not-a-uid"},
                                        {"companyUid": None}, "x", [A]])
def test_missing_configured_uid_is_not_evaluated(name, key, configured):
    good = body_for(name, A)
    body = {k: v for k, v in good.items() if k != "configuredSettings"} if configured == "absent" else \
        dict(good, configuredSettings=configured)
    v, out = run(name, key, body)
    assert v is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_unattributable_vm_job_never_names_another_company():
    """The console ignores the filter and returns another company's VM job without its embedded
    backupServerJob: the result is not evaluated, and no reason text names that job."""
    foreign = {"instanceUid": "foreign-vm-uid", "name": "foreign-vm-job", "targetRepositoryUid": "rb",
               "protectedVmCount": 9}
    body = targets_body(A, vm_jobs=[foreign] + CONSOLE_VM_JOBS)
    v, out = run("isbackupimmutable", "isBackupImmutable", body)
    assert v is None
    text = str(out)
    assert "foreign-vm-job" not in text and "foreign-vm-uid" not in text
    assert "b-vm" not in text and B not in text


def digits(text):
    return [c for c in str(text) if c.isdigit()]


@pytest.mark.parametrize("name,key", ALL)
def test_ambiguous_company_reason_carries_no_count(name, key):
    """Several companies back for one UID: the reason must not say how many companies the console holds."""
    for n in (2, 3, 7):
        many = coll([{"instanceUid": ("%08d" % i) + A[8:]} for i in range(n)])
        v, out = run(name, key, dict(body_for(name, A), company=many))
        assert v is None
        reason = out["additionalInfo"]["dataCollection"]["errors"][0]
        assert digits(reason) == [], reason


def test_unattributable_vm_job_reason_carries_no_count():
    foreign = [{"instanceUid": "f%d" % i, "targetRepositoryUid": "rb"} for i in range(4)]
    v, out = run("isbackupimmutable", "isBackupImmutable", targets_body(A, vm_jobs=foreign + CONSOLE_VM_JOBS))
    assert v is None
    reason = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert digits(reason) == [], reason
    assert "4" not in str(out["transformedResponse"])


@pytest.mark.parametrize("name,key", JOB_CHECKS)
def test_unattributed_job_is_not_evaluated(name, key):
    """A job with no organizationUid may be anyone's (and, for B, could be its unscheduled one):
    the check is not evaluated rather than judged on the attributable rest."""
    stray = job("stray", None, SRV_A, enabled=True, schedule="NotScheduled")
    del stray["organizationUid"]
    for org_value in ("absent", None, "", 7):
        j = dict(stray)
        if org_value != "absent":
            j["organizationUid"] = org_value
        v, out = run(name, key, jobs_body(A, jobs=CONSOLE_JOBS + [j]))
        assert v is None, (org_value, out["additionalInfo"]["dataCollection"])
        assert digits(out["additionalInfo"]["dataCollection"]["errors"][0]) == []


def test_unscheduled_unattributed_job_cannot_leave_scheduled_true():
    stray = job("stray", A, SRV_A, enabled=True, schedule="NotScheduled")
    del stray["organizationUid"]
    assert value("isbackuptypesscheduled", "isBackupTypesScheduled", jobs_body(A)) is True
    assert value("isbackuptypesscheduled", "isBackupTypesScheduled", jobs_body(A, jobs=CONSOLE_JOBS + [stray])) is None


@pytest.mark.parametrize("missing", ["type", "status"])
@pytest.mark.parametrize("how", ["absent", None, ""])
def test_licence_with_a_missing_field_is_not_evaluated(missing, how):
    bad = lic(SRV_A)
    if how == "absent":
        del bad[missing]
    else:
        bad[missing] = how
    v, out = run("confirmedlicensepurchased", "confirmedLicensePurchased", lic_body(A, licenses=[lic(SRV_A), bad]))
    assert v is None, out["additionalInfo"]["dataCollection"]
    # A real, readable "no" still fails.
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, licenses=[lic(SRV_A), lic(SRV_A, "Evaluation")])) is False


@pytest.mark.parametrize("how", ["absent", None, ""])
def test_enabled_job_with_a_missing_schedule_type_is_not_evaluated(how):
    j = recent_job("a-noschedule", A, SRV_A)
    if how == "absent":
        del j["scheduleType"]
    else:
        j["scheduleType"] = how
    v, out = run("isbackuptypesscheduled", "isBackupTypesScheduled", jobs_body(A, jobs=CONSOLE_JOBS + [j]))
    assert v is None, out["additionalInfo"]["dataCollection"]
    # A real unscheduled job is still a readable "no".
    assert value("isbackuptypesscheduled", "isBackupTypesScheduled",
                 jobs_body(A, jobs=CONSOLE_JOBS + [job("a-ns", A, SRV_A, schedule="NotScheduled")])) is False


@pytest.mark.parametrize("org_value", ["absent", None, "", 7])
def test_owner_less_embedded_vm_job_is_not_evaluated(org_value):
    """An embedded backupServerJob with no readable organizationUid may be anyone's: one owned immutable
    job plus one owner-less job on a mutable target is not evaluated, never True."""
    owned = vm_job("a-vm", A, SRV_A, "ra")
    stray = vm_job("stray-vm", A, SRV_A, "rm")
    if org_value == "absent":
        del stray["_embedded"]["backupServerJob"]["organizationUid"]
    else:
        stray["_embedded"]["backupServerJob"]["organizationUid"] = org_value
    repos = [repo("ra", SRV_A, True), repo("rm", SRV_A, False)]
    assert value("isbackupimmutable", "isBackupImmutable", targets_body(A, vm_jobs=[owned], repos=repos)) is True
    v, out = run("isbackupimmutable", "isBackupImmutable", targets_body(A, vm_jobs=[owned, stray], repos=repos))
    assert v is None, out["additionalInfo"]["dataCollection"]
    reason = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert digits(reason) == [] and "stray-vm" not in str(out)



# ── round 5: missing ownership data or a missing field is never a verdict ────

def drop(d, path):
    """Copy of d with the dotted key removed."""
    d = copy.deepcopy(d)
    cur = d
    parts = path.split(".")
    for p in parts[:-1]:
        cur = cur[p]
    del cur[parts[-1]]
    return d


IMM_REPOS = [repo("ra", SRV_A, True), repo("rm", SRV_A, False)]


def imm(vm_jobs, repos=None, servers=None):
    return targets_body(A, vm_jobs=vm_jobs, repos=IMM_REPOS if repos is None else repos, servers=servers)


def test_immutable_own_job_missing_its_server_is_not_evaluated():
    owned = vm_job("a-vm", A, SRV_A, "ra")
    stray = drop(vm_job("a-stray", A, SRV_A, "rm"), "_embedded.backupServerJob.backupServerUid")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned])) is True
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned, stray])) is None
    # Real "no": an own enabled job on a mutable target.
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned, vm_job("a-m", A, SRV_A, "rm")])) is False


@pytest.mark.parametrize("enabled", ["absent", None, "yes", 1])
def test_immutable_own_job_with_unreadable_is_enabled_is_not_evaluated(enabled):
    owned = vm_job("a-vm", A, SRV_A, "ra")
    stray = vm_job("a-stray", A, SRV_A, "rm")
    if enabled == "absent":
        stray = drop(stray, "_embedded.backupServerJob.isEnabled")
    else:
        stray["_embedded"]["backupServerJob"]["isEnabled"] = enabled
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned, stray])) is None
    # A real disabled job does not count.
    assert value("isbackupimmutable", "isBackupImmutable",
                 imm([owned, vm_job("a-off", A, SRV_A, "rm", enabled=False)])) is True


def test_immutable_repository_without_a_server_is_not_evaluated():
    """Scoped to repositories that could be the company's (master, pre-merge data concern)."""
    owned = vm_job("a-vm", A, SRV_A, "ra")
    # No server, and its UID is a target of the company's own job: cannot be ruled out.
    related = drop(repo("ra", SRV_A, False), "backupServerUid")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=IMM_REPOS + [related])) is None
    # No server and no link to any of the company's jobs: ruled out, the company is evaluated normally.
    unrelated = drop(repo("rx", SRV_A, False), "backupServerUid")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=IMM_REPOS + [unrelated])) is True
    # On one of the company's own servers but with no UID (it could be an extent): not evaluated.
    no_uid = drop(repo("ry", SRV_A, False), "instanceUid")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=IMM_REPOS + [no_uid])) is None
    # No UID on another company's server: ruled out.
    foreign_no_uid = drop(repo("rz", SRV_B, False), "instanceUid")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=IMM_REPOS + [foreign_no_uid])) is True


@pytest.mark.parametrize("flag", ["absent", None, "true"])
def test_immutable_missing_immutability_flag_is_not_evaluated(flag):
    owned = vm_job("a-vm", A, SRV_A, "ra")
    r = repo("ra", SRV_A, True)
    if flag == "absent":
        r = drop(r, "isImmutabilityEnabled")
    else:
        r["isImmutabilityEnabled"] = flag
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=[r])) is None
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=[repo("ra", SRV_A, False)])) is False


def test_licence_without_a_server_is_not_evaluated():
    orphan = drop(lic(SRV_A, "Evaluation"), "backupServerUid")
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased", lic_body(A, licenses=[lic(SRV_A)])) is True
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, licenses=[lic(SRV_A), orphan])) is None
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, licenses=[lic(SRV_A), lic(SRV_A, "Evaluation")])) is False


PROVIDER_SRV = "cccccccc-0000-4000-8000-00000000000c"


@pytest.mark.parametrize("name,key", [("confirmedlicensepurchased", "confirmedLicensePurchased"),
                                      ("isbackupimmutable", "isBackupImmutable")])
@pytest.mark.parametrize("org", ["absent", None, ""])
def test_ownerless_provider_server_unrelated_to_the_company_is_skipped(name, key, org):
    """One unassigned or provider-owned server (organizationUid null) on an MSP console must not
    make every company on it read Not evaluated: unrelated to the company, it is skipped."""
    stray = server(PROVIDER_SRV, A)
    if org == "absent":
        del stray["organizationUid"]
    else:
        stray["organizationUid"] = org
    body = body_for(name, A)
    extra = {"backupServers": coll(CONSOLE_SERVERS + [stray])}
    if name == "confirmedlicensepurchased":
        # Its licence (an evaluation one) is not the company's either.
        extra["licenses"] = coll(CONSOLE_LICENSES + [lic(PROVIDER_SRV, "Evaluation")])
    else:
        extra["repositories"] = coll(CONSOLE_REPOS + [repo("rp", PROVIDER_SRV, False)])
    assert value(name, key, dict(body, **extra)) is True
    assert value(name, key, dict(body_for(name, B), **extra)) is False


def test_ownerless_server_the_company_job_points_at_is_not_evaluated():
    stray = server(PROVIDER_SRV, A)
    stray["organizationUid"] = None
    jobs = CONSOLE_VM_JOBS + [vm_job("a-hosted", A, PROVIDER_SRV, "rp")]
    body = targets_body(A, servers=CONSOLE_SERVERS + [stray], vm_jobs=jobs,
                        repos=CONSOLE_REPOS + [repo("rp", PROVIDER_SRV, False)])
    v, out = run("isbackupimmutable", "isBackupImmutable", body)
    assert v is None
    assert digits(out["additionalInfo"]["dataCollection"]["errors"][0]) == []


def test_own_vm_job_on_a_server_outside_the_company_is_not_evaluated():
    """The company's own job on another company's server (inconsistent data) could hide a mutable
    target: not evaluated, never skipped."""
    owned = vm_job("a-vm", A, SRV_A, "ra")
    elsewhere = vm_job("a-elsewhere", A, SRV_B, "rb")
    assert value("isbackupimmutable", "isBackupImmutable", targets_body(A, vm_jobs=[owned])) is True
    assert value("isbackupimmutable", "isBackupImmutable", targets_body(A, vm_jobs=[owned, elsewhere])) is None
    # Another company's job on another company's server is still simply not this company's.
    assert value("isbackupimmutable", "isBackupImmutable",
                 targets_body(A, vm_jobs=[owned, vm_job("b-vm", B, SRV_B, "rb")])) is True


@pytest.mark.parametrize("name,key", [("confirmedlicensepurchased", "confirmedLicensePurchased"),
                                      ("isbackupimmutable", "isBackupImmutable")])
def test_company_server_without_a_uid_is_not_evaluated(name, key):
    """A server the company owns but whose UID cannot be read hides its licences or repositories."""
    stray = drop(server(PROVIDER_SRV, A), "instanceUid")
    good = body_for(name, A)
    v, out = run(name, key, dict(good, backupServers=coll(CONSOLE_SERVERS + [stray])))
    assert v is None
    assert digits(out["additionalInfo"]["dataCollection"]["errors"][0]) == []
    # The same server without a UID and without an owner cannot be the company's: skipped.
    nobody = drop(stray, "organizationUid")
    assert value(name, key, dict(good, backupServers=coll(CONSOLE_SERVERS + [nobody]))) is True


@pytest.mark.parametrize("missing", ["isEnabled", "type"])
def test_backup_enabled_missing_field_is_not_evaluated(missing):
    only_off = [job("a-off", A, SRV_A, enabled=False)]
    assert value("isbackupenabled", "isBackupEnabled", jobs_body(A, jobs=only_off)) is False
    stray = drop(job("a-x", A, SRV_A), missing)
    assert value("isbackupenabled", "isBackupEnabled", jobs_body(A, jobs=only_off + [stray])) is None
    # A readable enabled job still answers True whatever else is missing.
    assert value("isbackupenabled", "isBackupEnabled", jobs_body(A, jobs=[job("a-on", A, SRV_A), stray])) is True


@pytest.mark.parametrize("change", ["no-status", "no-times", "no-type", "no-enabled"])
def test_backup_tested_missing_field_is_not_evaluated(change):
    failed = job("a-sb-failed", A, SRV_A, jtype="SureBackup", status="Failed")
    assert value("isbackuptested", "isBackupTested", jobs_body(A, jobs=[failed])) is False
    sb = recent_job("a-sb", A, SRV_A, jtype="SureBackup")
    if change == "no-status":
        sb = drop(sb, "status")
    elif change == "no-times":
        sb["lastEndTime"] = None
        sb["lastRun"] = "not a time"
    elif change == "no-type":
        sb = drop(sb, "type")
    else:
        sb = drop(sb, "isEnabled")
    assert value("isbackuptested", "isBackupTested", jobs_body(A, jobs=[failed, sb])) is None


@pytest.mark.parametrize("missing", ["type", "isEnabled"])
def test_types_scheduled_missing_field_is_not_evaluated(missing):
    good = [job("a-ok", A, SRV_A)]
    assert value("isbackuptypesscheduled", "isBackupTypesScheduled", jobs_body(A, jobs=good)) is True
    stray = drop(job("a-x", A, SRV_A, schedule="NotScheduled"), missing)
    assert value("isbackuptypesscheduled", "isBackupTypesScheduled", jobs_body(A, jobs=good + [stray])) is None
    assert value("isbackuptypesscheduled", "isBackupTypesScheduled",
                 jobs_body(A, jobs=good + [job("a-ns", A, SRV_A, schedule="NotScheduled")])) is False


@pytest.mark.parametrize("name,key", ALL)
def test_partial_read_reason_carries_no_console_count(name, key):
    part = {"isbackupimmutable": "repositories", "confirmedlicensepurchased": "licenses"}.get(name, "jobs")
    body = body_for(name, A)
    items = body[part]["data"]
    v, out = run(name, key, dict(body, **{part: coll(items, total=4321)}))
    assert v is None
    reason = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert digits(reason) == [], reason


@pytest.mark.parametrize("name,key", ALL)
def test_vendor_error_text_is_not_echoed(name, key):
    secret = "vendor-internal-detail-xyz"
    body = body_for(name, A)
    part = {"isbackupimmutable": "vmJobs", "confirmedlicensepurchased": "licenses"}.get(name, "jobs")
    err = {"meta": None, "data": None, "errors": [{"message": secret, "type": "security", "code": 1100}]}
    v, out = run(name, key, dict(body, **{part: err}))
    assert v is None and secret not in str(out)


def test_repository_without_a_server_is_ruled_out_only_without_an_enabled_company_job_on_it():
    owned = vm_job("a-vm", A, SRV_A, "ra")
    off = vm_job("a-off", A, SRV_A, "rx", enabled=False)
    orphan = drop(repo("rx", SRV_A, False), "backupServerUid")
    # Only a disabled company job targets it: ruled out.
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned, off], repos=IMM_REPOS + [orphan])) is True
    # An enabled company job targets it: not evaluated.
    on = vm_job("a-on", A, SRV_A, "rx")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned, on], repos=IMM_REPOS + [orphan])) is None


def test_licence_without_a_server_is_ruled_out_only_by_an_owner_field():
    """VSPC licences carry no organization field (v3.6.1 schema), so in practice a licence without a
    backupServerUid is Not evaluated. If one ever names another owner, it is ruled out."""
    orphan = drop(lic(SRV_A, "Evaluation"), "backupServerUid")
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, licenses=[lic(SRV_A), orphan])) is None
    other = dict(orphan, organizationUid=B)
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, licenses=[lic(SRV_A), other])) is True
    own = dict(orphan, organizationUid=A)
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased",
                 lic_body(A, licenses=[lic(SRV_A), own])) is None


def test_serverless_extent_of_a_targeted_scale_out_is_not_evaluated():
    """A scale-out extent with no backupServerUid under a targeted (or company-owned) parent could be a
    mutable extent of the company's target: not evaluated, never True."""
    owned = vm_job("a-vm", A, SRV_A, "s1")
    sobr = repo("s1", SRV_A, None, "ScaleOut")
    e1 = dict(repo("e1", SRV_A, True), parentRepositoryUid="s1")
    e2 = drop(dict(repo("e2", SRV_A, False), parentRepositoryUid="s1"), "backupServerUid")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=[sobr, e1])) is True
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=[sobr, e1, e2])) is None
    # Parent not targeted but on a company server: still not evaluated.
    other_sobr = repo("s2", SRV_A, None, "ScaleOut")
    e3 = drop(dict(repo("e3", SRV_A, False), parentRepositoryUid="s2"), "backupServerUid")
    assert value("isbackupimmutable", "isBackupImmutable",
                 imm([owned], repos=[sobr, e1, other_sobr, e3])) is None


def test_serverless_extent_of_an_unrelated_parent_stays_skipped():
    owned = vm_job("a-vm", A, SRV_A, "s1")
    sobr = repo("s1", SRV_A, None, "ScaleOut")
    e1 = dict(repo("e1", SRV_A, True), parentRepositoryUid="s1")
    foreign_sobr = repo("sb", SRV_B, None, "ScaleOut")
    stray = drop(dict(repo("eb", SRV_B, False), parentRepositoryUid="sb"), "backupServerUid")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=[sobr, e1, foreign_sobr, stray])) is True
    orphan = drop(dict(repo("ez", SRV_B, False), parentRepositoryUid="nowhere"), "backupServerUid")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=[sobr, e1, orphan])) is True


@pytest.mark.parametrize("rtype", ["absent", None, "", 3])
def test_target_whose_type_cannot_be_read_is_not_evaluated(rtype):
    """A target that may be a scale-out repository (type unreadable) cannot be judged as a single
    repository: its extents could be mutable."""
    owned = vm_job("a-vm", A, SRV_A, "s1")
    target = repo("s1", SRV_A, True, "ScaleOut")
    if rtype == "absent":
        del target["type"]
    else:
        target["type"] = rtype
    extent = dict(repo("e1", SRV_A, False), parentRepositoryUid="s1")
    assert value("isbackupimmutable", "isBackupImmutable", imm([owned], repos=[target, extent])) is None
    # A readable single-repository type is judged as before.
    assert value("isbackupimmutable", "isBackupImmutable",
                 imm([owned], repos=[repo("s1", SRV_A, True, "LinuxHardened")])) is True


@pytest.mark.parametrize("name", ["isbackupenabled", "isbackuptested", "isbackuptypesscheduled"])
def test_job_checks_carry_no_unused_server_scoping(name):
    """The three job checks never read backupServers; the copied company_servers helper is gone."""
    with open(os.path.join(HERE, name + ".py")) as fh:
        assert "def company_servers" not in fh.read()
