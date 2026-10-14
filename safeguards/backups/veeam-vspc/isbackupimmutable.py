"""Transformation: isBackupImmutable - Veeam Service Provider Console REST API v3.
Source: workflow getRepositoryTargets: company + GET /api/v3/infrastructure/backupServers filtered by
organizationUid (backupServers) + GET .../jobs/backupVmJobs?expand=BackupServerJob (vmJobs) +
GET /api/v3/infrastructure/backupServers/repositories (repositories).
One company only: the "company" part (GET /api/v3/organizations/companies filtered by the connection's
Company UID) must name exactly one company, and it must equal the Company UID Integration-Service echoes
under "configuredSettings"; otherwise (no Company UID, a mismatch) the check is None, never a verdict
over the whole console. Only VM jobs the
company owns on its own servers, and repositories on those servers, count.
True when every repository written by an enabled VM backup job has immutability enabled (for a
scale-out repository: every extent). False when any target is mutable. None when there is no enabled
VM backup job or a target cannot be resolved in the repository list.
Returns None (not measured) on any body that is not a complete VSPC read: empty, an error envelope,
an unrelated body, or a partial page set."""
import json
from datetime import datetime, timedelta, timezone

KEY = "isBackupImmutable"
METHOD = "getRepositoryTargets"

VENDOR = "Veeam"
PRODUCT = "Veeam Service Provider Console (REST API v3)"
WRAPPERS = ["apiResponse", "api_response", "response", "result", "Output", "_response_data"]


def to_obj(raw):
    """A parsed JSON value, or None for an empty or unparseable body."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        text = raw.strip()
        if text == "":
            return None
        try:
            return json.loads(text)
        except Exception:
            return None
    return raw


def envelope_error(obj):
    """A short reason when obj is an IS or VSPC error envelope, else None."""
    if not isinstance(obj, dict):
        return None
    errs = obj.get("errors")
    if isinstance(errs, list) and len(errs) > 0:
        first = errs[0] if isinstance(errs[0], dict) else {}
        return "VSPC returned an error: " + str(first.get("message") or first.get("type") or errs[0])[:300]
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        detail = obj.get("message") or err
        if isinstance(detail, dict):
            detail = detail.get("message") or json.dumps(detail)[:200]
        return "The VSPC call did not return data: " + str(detail)[:300]
    code = obj.get("status_code") or obj.get("statusCode") or obj.get("status")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "The VSPC call returned HTTP " + str(code)
    if obj.get("status") == "Error":
        return "The VSPC call did not return data: " + str(obj.get("message") or "error")[:300]
    return None


def is_collection(obj):
    return isinstance(obj, dict) and isinstance(obj.get("data"), list) and isinstance(obj.get("meta"), dict)


def find_collection(raw):
    """(collection dict, None) or (None, reason). A VSPC v3 collection is
    {"meta": {"pagingInfo": {"total", "count", "offset"}}, "data": [...], "errors": null}.
    Token-Service may pass {"data": <body>, "validation": {...}}; IS may wrap it in apiResponse."""
    cur = to_obj(raw)
    for depth in range(8):
        if cur is None:
            return None, "The response body is empty"
        if not isinstance(cur, dict):
            return None, "The response is not a JSON object"
        problem = envelope_error(cur)
        if problem is not None:
            return None, problem
        if is_collection(cur):
            return cur, None
        nxt = None
        if "validation" in cur and "data" in cur and not isinstance(cur.get("data"), list):
            nxt = to_obj(cur.get("data"))
        else:
            for w in WRAPPERS:
                if isinstance(cur.get(w), (dict, str)):
                    nxt = to_obj(cur.get(w))
                    break
            if nxt is None and isinstance(cur.get("data"), (dict, str)):
                nxt = to_obj(cur.get("data"))
        if nxt is None:
            return None, "No VSPC collection (meta + data array) in the response; nothing to evaluate"
        cur = nxt
    return None, "No VSPC collection found within 8 levels of wrapping"


def complete_items(raw, what):
    """(items, None) for a complete VSPC collection read, else (None, reason).
    Complete: every entry an object and len(data) >= meta.pagingInfo.total."""
    coll, why = find_collection(raw)
    if why:
        return None, what + ": " + why
    items = coll.get("data")
    paging = coll.get("meta", {}).get("pagingInfo")
    total = paging.get("total") if isinstance(paging, dict) else None
    if isinstance(total, bool) or not isinstance(total, int):
        return None, what + ": no meta.pagingInfo.total, so a complete read cannot be shown"
    if len(items) < total:
        return None, what + ": read " + str(len(items)) + " of " + str(total) + "; the remaining pages were not read"
    for it in items:
        if not isinstance(it, dict):
            return None, what + ": an entry is not an object"
    return items, None


def workflow_part(raw, key):
    """The named part of a merged workflow body ({"vmJobs": ..., "repositories": ...}), or None."""
    cur = to_obj(raw)
    for depth in range(8):
        if not isinstance(cur, dict):
            return None
        if key in cur:
            return cur.get(key)
        nxt = None
        if "validation" in cur and "data" in cur:
            nxt = to_obj(cur.get("data"))
        else:
            for w in WRAPPERS:
                if isinstance(cur.get(w), (dict, str)):
                    nxt = to_obj(cur.get(w))
                    break
        if nxt is None:
            return None
        cur = nxt
    return None


HEX = "0123456789abcdef"


def is_uid(value):
    """True for a VSPC UID: 36 characters, hex in 8-4-4-4-12 groups."""
    if not isinstance(value, str) or len(value) != 36:
        return False
    low = value.lower()
    for i in range(36):
        if i in (8, 13, 18, 23):
            if low[i] != "-":
                return False
        elif low[i] not in HEX:
            return False
    return True


def lower_text(value):
    return value.lower() if isinstance(value, str) else None


def part_error(raw):
    """An error envelope at the top of the body (Integration-Service stopped the workflow), else None."""
    cur = to_obj(raw)
    for depth in range(8):
        if not isinstance(cur, dict):
            return None
        problem = envelope_error(cur)
        if problem is not None:
            return problem
        nxt = None
        if "validation" in cur and "data" in cur:
            nxt = to_obj(cur.get("data"))
        else:
            for w in WRAPPERS:
                if isinstance(cur.get(w), (dict, str)):
                    nxt = to_obj(cur.get(w))
                    break
        if nxt is None:
            return None
        cur = nxt
    return None


def configured_company(raw):
    """(company UID, None) from the workflow's "company" part, else (None, reason).
    The part is GET /organizations/companies filtered by the connection's Company UID: exactly one
    company with a UID, read completely. Anything else (no Company UID, so no company read; no match;
    several companies because the filter was not applied; an error) is not evaluated."""
    part = workflow_part(raw, "company")
    if part is None:
        problem = part_error(raw)
        if problem is not None:
            return None, problem
        return None, ("No company read in the response. The connection needs its Company UID (VSPC portal: "
                      "Companies > the company > UID) so only that company is evaluated, never the whole console")
    items, why = complete_items(part, "company")
    if why:
        return None, why
    if len(items) != 1:
        return None, ("The Company UID matched " + str(len(items)) + " companies on the console; exactly one is "
                      "needed to evaluate one company")
    uid = items[0].get("instanceUid")
    if not is_uid(uid):
        return None, "The company read carries no valid instanceUid"
    # The company VSPC returned must be the one the connection names (Integration-Service echoes the
    # Company UID under configuredSettings). A console that ignores the filter and holds one company
    # would otherwise answer with it whatever UID was asked for.
    asked = configured_uid(raw)
    if asked is None:
        return None, ("No configured Company UID in the response, so the company VSPC returned cannot be "
                      "shown to be the one this connection names")
    if uid.lower() != asked:
        return None, "The company VSPC returned does not match the connection's Company UID"
    return uid.lower(), None


def configured_uid(raw):
    """The connection's Company UID as Integration-Service echoed it (output.echoSettings), or None."""
    conf = workflow_part(raw, "configuredSettings")
    if not isinstance(conf, dict):
        return None
    uid = conf.get("companyUid")
    if not is_uid(uid):
        return None
    return uid.lower()


def company_servers(raw, company):
    """({backup server UID: True}, None) for the company's own Veeam Backup & Replication servers, else
    (None, reason). Only servers whose organizationUid is the company count, whatever else is listed."""
    part = workflow_part(raw, "backupServers")
    if part is None:
        return None, "No backup server read for the company; repositories and licenses cannot be scoped to it"
    items, why = complete_items(part, "company backup servers")
    if why:
        return None, why
    owned = {}
    for s in items:
        uid = lower_text(s.get("instanceUid"))
        if uid and lower_text(s.get("organizationUid")) == company:
            owned[uid] = True
    if len(owned) == 0:
        return None, "The company has no Veeam Backup & Replication server on this console; nothing to evaluate"
    return owned, None


def company_jobs(jobs, company):
    """The jobs the company owns (BackupServerJob.organizationUid), and whether the console's filter
    already returned only those."""
    own = [j for j in jobs if lower_text(j.get("organizationUid")) == company]
    return own, len(own) == len(jobs)


def parse_time(value):
    """Naive-UTC datetime from a VSPC timestamp ("2023-10-20 03:07:31.317000+02:00" or ISO with T/Z).
    None if unreadable."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    t = value.strip()
    try:
        base = datetime(int(t[0:4]), int(t[5:7]), int(t[8:10]), int(t[11:13]), int(t[14:16]), int(t[17:19]))
    except Exception:
        return None
    tail = t[19:]
    sign = 0
    pos = -1
    for i in range(len(tail)):
        if tail[i] in "+-":
            pos = i
            sign = 1 if tail[i] == "+" else -1
            break
    if pos >= 0:
        off = tail[pos + 1:].replace(":", "")
        if len(off) < 4 or not off[:4].isdigit():
            return None
        minutes = int(off[0:2]) * 60 + int(off[2:4])
        return base - timedelta(minutes=sign * minutes)
    return base


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def name_of(obj):
    return str(obj.get("name") or obj.get("instanceUid") or "?")


def respond(key, method, value, reason, extra=None):
    """2.0 response. value None = not measured: dataCollection.status error, no verdict."""
    result = {key: value}
    if extra:
        for k in extra:
            result[k] = extra[k]
    measured = value is not None
    passed = value is True
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [],
                           "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": VENDOR, "product": PRODUCT, "method": method,
                         "evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "2.0"},
        },
    }


BACKUP_TYPES = ["BackupVm", "AgentBackupJob", "AgentPolicy", "BackupFile", "AzureBackupJob", "AwsBackupJob",
                "GoogleBackupJob", "ObjectStorageBackup"]
SCHEDULED = ["Daily", "Monthly", "Periodically", "Continuously", "BackupWindow", "Chained"]

def evaluate(input):
    company, why = configured_company(input)
    if why:
        return respond(KEY, METHOD, None, why)
    servers, why = company_servers(input, company)
    if why:
        return respond(KEY, METHOD, None, why)
    all_vm_jobs, why = complete_items(workflow_part(input, "vmJobs"), "VM backup jobs")
    if why:
        return respond(KEY, METHOD, None, why)
    all_repos, why = complete_items(workflow_part(input, "repositories"), "backup repositories")
    if why:
        return respond(KEY, METHOD, None, why)
    repos = [r for r in all_repos if servers.get(lower_text(r.get("backupServerUid")) or "") is True]
    by_uid = {}
    for r in repos:
        by_uid[(str(r.get("backupServerUid")).lower(), str(r.get("instanceUid")).lower())] = r
    enabled = []
    owned_jobs = 0
    unattributed = 0
    for j in all_vm_jobs:
        emb = j.get("_embedded") if isinstance(j.get("_embedded"), dict) else {}
        job = emb.get("backupServerJob") if isinstance(emb.get("backupServerJob"), dict) else None
        if job is None:
            # Its owner cannot be read, so it may be another company's: counted, never named.
            unattributed = unattributed + 1
            continue
        # The company's own job on one of the company's own servers; anything else is another company's.
        if lower_text(job.get("organizationUid")) != company:
            continue
        if servers.get(lower_text(job.get("backupServerUid")) or "") is not True:
            continue
        owned_jobs = owned_jobs + 1
        if job.get("isEnabled") is True:
            enabled.append((j, job))
    if unattributed > 0:
        return respond(KEY, METHOD, None, str(unattributed) + " VM backup jobs carry no embedded backupServerJob "
                       "(expand=BackupServerJob was not applied), so their owner cannot be shown")
    if len(enabled) == 0:
        return respond(KEY, METHOD, None, "No enabled VM backup job of the company, so no repository target to judge")
    mutable = []
    checked = 0
    for j, job in enabled:
        server = str(job.get("backupServerUid")).lower()
        target = by_uid.get((server, str(j.get("targetRepositoryUid")).lower()))
        if target is None:
            return respond(KEY, METHOD, None, "Target repository of job " + name_of(job) +
                           " is not in the company's repository list")
        if target.get("type") == "ScaleOut":
            extents = [r for r in repos if str(r.get("backupServerUid")).lower() == server and
                       str(r.get("parentRepositoryUid")).lower() == str(target.get("instanceUid")).lower()]
            if len(extents) == 0:
                return respond(KEY, METHOD, None, "Scale-out repository " + name_of(target) + " lists no extents")
        else:
            extents = [target]
        for r in extents:
            checked = checked + 1
            if r.get("isImmutabilityEnabled") is not True:
                mutable.append(name_of(job) + " -> " + name_of(r) + " (" + str(r.get("type")) + ")")
    extra = {"enabledVmBackupJobCount": len(enabled), "targetsChecked": checked, "mutableTargetCount": len(mutable),
             "consoleFilterHonoured": owned_jobs == len(all_vm_jobs) and len(repos) == len(all_repos)}
    if mutable:
        extra["mutableTargets"] = mutable[:25]
        return respond(KEY, METHOD, False, str(len(mutable)) + " job targets of the company do not have immutability "
                       "enabled", extra)
    return respond(KEY, METHOD, True, "Every repository written by the " + str(len(enabled)) +
                   " enabled VM backup jobs of the company has immutability enabled", extra)


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled response as {"data": <response>, "validation": ...}. Without it Token-Service drills into the
    # VSPC "data" array and meta.pagingInfo (the completeness proof) is lost.
    try:
        if isinstance(input, dict) and "validation" in input and not isinstance(input.get("data"), list):
            input = input.get("data")
        return evaluate(input)
    except Exception as e:
        return respond(KEY, METHOD, None, "Transformation error: " + str(e)[:300])
