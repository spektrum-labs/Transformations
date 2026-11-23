"""Transformation: isBackupTypesScheduled - Veeam Service Provider Console REST API v3.
Source: workflow getCompanyJobs: company + GET /api/v3/infrastructure/backupServers/jobs filtered by
organizationUid (jobs, all pages).
One company only: the "company" part (GET /api/v3/organizations/companies filtered by the connection's
Company UID) must name exactly one company, and it must equal the Company UID Integration-Service echoes
under "configuredSettings"; otherwise (no Company UID, a mismatch) the check is None, never a verdict
over the whole console. Only jobs whose organizationUid is the company count (a safety net:
the VSPC filter is unproven against a real console); none of them is None.
True when there is at least one enabled backup job and every enabled backup job has a schedule
(scheduleType Daily, Monthly, Periodically, Continuously, BackupWindow or Chained).
Returns None (not measured) on any body that is not a complete VSPC read: empty, an error envelope,
an unrelated body, or a partial page set."""
import json
from datetime import datetime, timedelta, timezone

KEY = "isBackupTypesScheduled"
METHOD = "getCompanyJobs"

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
    # Fixed reasons: the vendor's own error text is never echoed into the result.
    errs = obj.get("errors")
    if isinstance(errs, list) and len(errs) > 0:
        return "VSPC returned an error"
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        return "The VSPC call did not return data"
    code = obj.get("status_code") or obj.get("statusCode") or obj.get("status")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "The VSPC call returned HTTP " + str(code)
    if obj.get("status") == "Error":
        return "The VSPC call did not return data"
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
        # No numbers: the total can be the whole console's count, across companies.
        return None, what + ": only part of the list was read; the remaining pages were not read"
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


def is_text(value):
    """A readable, non-blank string field."""
    return isinstance(value, str) and value.strip() != ""


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
        return None, ("The Company UID did not match exactly one company on the console, so no single "
                      "company can be evaluated")
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


def company_jobs(jobs, company):
    """(the jobs the company owns, whether any job has no readable owner). A job without an
    organizationUid may be anyone's, so a check must not judge the attributable rest without it."""
    own = []
    unattributed = False
    for j in jobs:
        org = lower_text(j.get("organizationUid"))
        if not org:
            unattributed = True
        elif org == company:
            own.append(j)
    return own, unattributed


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
    jobs, why = complete_items(workflow_part(input, "jobs"), "backup server jobs")
    if why:
        return respond(KEY, METHOD, None, why)
    jobs, unattributed = company_jobs(jobs, company)
    if unattributed:
        return respond(KEY, METHOD, None, "Some jobs on the console carry no organizationUid, so the company's "
                       "own jobs cannot be shown completely")
    if len(jobs) == 0:
        return respond(KEY, METHOD, None, "VSPC lists no job of the company; nothing to evaluate")
    enabled = [j for j in jobs if j.get("type") in BACKUP_TYPES and j.get("isEnabled") is True]
    unread_jobs = [j for j in jobs if not is_text(j.get("type"))] + \
        [j for j in jobs if j.get("type") in BACKUP_TYPES and not isinstance(j.get("isEnabled"), bool)]
    if len(enabled) == 0 and unread_jobs:
        return respond(KEY, METHOD, None, "Some jobs of the company report no type or isEnabled, so which backup "
                       "jobs are enabled cannot be shown")
    if len(enabled) == 0:
        return respond(KEY, METHOD, False, "No enabled backup job of the company, so no backup is scheduled",
                       {"enabledBackupJobCount": 0})
    unscheduled = [name_of(j) + " (" + str(j.get("scheduleType")) + ")" for j in enabled
                   if is_text(j.get("scheduleType")) and j.get("scheduleType") not in SCHEDULED]
    unread = [j for j in enabled if not is_text(j.get("scheduleType"))]
    extra = {"enabledBackupJobCount": len(enabled), "unscheduledJobCount": len(unscheduled)}
    if unscheduled:
        extra["unscheduledJobs"] = unscheduled[:25]
        return respond(KEY, METHOD, False, str(len(unscheduled)) + " of " + str(len(enabled)) +
                       " enabled backup jobs of the company have no schedule", extra)
    if unread_jobs:
        return respond(KEY, METHOD, None, "Some jobs of the company report no type or isEnabled, so which backup "
                       "jobs are enabled cannot be shown")
    if unread:
        return respond(KEY, METHOD, None, "Some enabled backup jobs of the company report no scheduleType, so "
                       "whether they run on a schedule cannot be shown")
    return respond(KEY, METHOD, True, "All " + str(len(enabled)) + " enabled backup jobs of the company run on a "
                   "schedule", extra)


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
