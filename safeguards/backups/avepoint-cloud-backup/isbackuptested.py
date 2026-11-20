"""Transformation: isBackupTested
Vendor: AvePoint  |  Category: Backups  |  Product: AvePoint Cloud Backup for Microsoft 365
Method: listRestoreJobs

  GET {serverUrl}/backup/m365/cloudbackupjobs?jobType=2&startTime={$utcNow-365d}&pageSize=50
  (jobType 2 = Restore; paged by metadata.nextLink)
  Permission: microsoft365backup.jobInfo.read.all
  https://learn.avepoint.com/docs/services-and-features/m365/jobs/list-jobs.html

Documented body: {"statusCode": 200, "message": "", "data": [{"id", "state", "startTime", "finishTime",
"duration", "backupDetails": {...counts...}, "jobErrors": [...]}, ...], "metadata": {"totalCount": <int>,
"nextLink": "<url or empty>"}, "requestId", "timestamp", "traceId"}. Job states (jobState filter values):
In Progress, Finished, Failed, Finished with Exception, Partially Finished.

True when at least one restore job finished with state "Finished" in the last 365 days (and, when AvePoint
reports a successful object count, restored at least one object). False when the restore job list was read
completely and none qualifies (no restore at all, or only failed / partial ones). None (Unevaluated) for a
missing, error, vendorErrorAsResponse or unrecognised body, a partial read (an unread metadata.nextLink,
paginationTruncated, metadata.truncated, or fewer jobs than metadata.totalCount), or a Finished restore whose
finish time cannot be read when nothing else qualifies.

Same meaning as the Druva and Rubrik transforms: a restore that completed recently shows the backups can be
recovered. The response carries no job type field, so this relies on AvePoint applying the documented
jobType=2 filter; the first live read must confirm that only restore jobs come back.
Does not prove: a scheduled restore-test programme, or that every service was restored.
"""

import json
import re
from datetime import datetime, timedelta, timezone

KEY = "isBackupTested"
METHOD = "listRestoreJobs"
ENDPOINT = "GET /backup/m365/cloudbackupjobs?jobType=2"
VENDOR = "AvePoint Cloud Backup for Microsoft 365"
CATEGORY = "Backups"
REQUIRED_PERMISSION = "microsoft365backup.jobInfo.read.all"
WINDOW_DAYS = 365
WRAPPER_KEYS = ["apiResponse", "api_response", "response", "result", "Output", "_response_data"]
ISO_UTC = r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|\+00:00)?$"


def decode(value):
    """A body as an object: dicts and lists as they are, JSON text or bytes parsed, else None."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except Exception:
            return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return None
    return value


def unwrap(value):
    """Strip the Integration-Service / Token-Service envelopes; the AvePoint body is left as it is."""
    value = decode(value)
    for step in range(5):
        if not isinstance(value, dict):
            return value
        if "validation" in value and "data" in value and isinstance(value.get("validation"), dict):
            value = decode(value.get("data"))
            continue
        moved = False
        for key in WRAPPER_KEYS:
            inner = value.get(key)
            if isinstance(inner, (dict, list, str, bytes)) and inner not in ("", b""):
                inner = decode(inner)
                if isinstance(inner, (dict, list)):
                    value = inner
                    moved = True
                    break
        if not moved:
            return value
    return value


def as_int(value):
    """An int that is not a bool, else None."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def vendor_problem(body):
    """Why this body is not evidence (a dict with status and text), or None when it is a successful read."""
    if not isinstance(body, dict):
        return None
    marker = body.get("vendorErrorAsResponse")
    if marker is not None:
        status = marker.get("status") if isinstance(marker, dict) else None
        return {"status": status, "text": "AvePoint refused the call"}
    if body.get("error") not in (None, False, "", 0):
        status = as_int(body.get("statusCode")) or as_int(body.get("status_code")) or as_int(body.get("status"))
        return {"status": status, "text": "Integration-Service returned an error for the call"}
    if body.get("paginationTruncated") is True:
        return {"status": None, "text": "the job list was cut short (paginationTruncated)"}
    status = as_int(body.get("statusCode"))
    if "statusCode" in body and status != 200:
        return {"status": status, "text": "AvePoint answered with statusCode " + str(body.get("statusCode"))[:10]}
    errors = body.get("errors")
    if isinstance(errors, list) and len(errors) > 0:
        return {"status": status, "text": "AvePoint returned " + str(len(errors)) + " API error(s)"}
    return None


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, additional_findings=None):
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": VENDOR,
                "category": CATEGORY,
                "method": METHOD,
            },
        },
    }


def not_evaluated(reason, problem=None):
    """Nothing was measured: the key is None (Unevaluated), never True and never False."""
    text = "Not evaluated: " + reason
    out = create_response({KEY: None}, fail_reasons=[text], api_errors=[text])
    status = problem.get("status") if isinstance(problem, dict) else None
    if status in (401, 403):
        out["additionalInfo"]["dataCollection"]["errorCode"] = "permission_not_granted"
        out["additionalInfo"]["dataCollection"]["requiredPermission"] = REQUIRED_PERMISSION
        out["additionalInfo"]["evaluation"]["recommendations"] = [
            "In AvePoint Online Services open Administration > App registrations, edit the Spektrum app and add "
            "the Cloud Backup for Microsoft 365 permission " + REQUIRED_PERMISSION + "."]
    return out


def parse_utc(text):
    """A UTC ISO 8601 timestamp ("2024-12-02T07:53:04Z") as an aware datetime, else None. No strptime."""
    if not isinstance(text, str):
        return None
    m = re.match(ISO_UTC, text.strip())
    if not m:
        return None
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                        int(m.group(6)), tzinfo=timezone.utc)
    except Exception:
        return None


def successful_count(job):
    """The documented successful object count (sample: successfulCount; table: successfulNumber), or None."""
    details = job.get("backupDetails")
    if not isinstance(details, dict):
        return None
    for field in ("successfulCount", "successfulNumber"):
        n = as_int(details.get(field))
        if n is not None:
            return n
    return None


def read_jobs(input):
    """(jobs, None) for a complete documented job list, else (None, (reason, problem))."""
    body = unwrap(input)
    if not isinstance(body, dict):
        return None, ("no " + ENDPOINT + " response was returned", None)
    problem = vendor_problem(body)
    if problem is not None:
        return None, (problem["text"] + " (" + ENDPOINT + "); nothing was measured.", problem)
    if as_int(body.get("statusCode")) != 200:
        return None, ("the " + ENDPOINT + " response has no statusCode 200, so it is not the documented body", None)
    jobs = body.get("data")
    if not isinstance(jobs, list):
        return None, ("the " + ENDPOINT + " response carries no data list", None)
    meta = body.get("metadata")
    if not isinstance(meta, dict):
        return None, ("the " + ENDPOINT + " response has no metadata block, so completeness cannot be checked", None)
    next_link = meta.get("nextLink")
    if isinstance(next_link, str) and next_link.strip():
        return None, ("the restore job list was only partly read (unread metadata.nextLink)", None)
    if meta.get("truncated") is True:
        return None, ("the restore job list was only partly read (page limit reached)", None)
    total = as_int(meta.get("totalCount"))
    if total is not None and total > len(jobs):
        return None, ("the restore job list was only partly read (" + str(len(jobs)) + " of " + str(total)
                      + " jobs)", None)
    return jobs, None


def measure(input):
    jobs, failure = read_jobs(input)
    if jobs is None:
        return not_evaluated(failure[0], failure[1])
    now = datetime.now(timezone.utc)
    oldest = now - timedelta(days=WINDOW_DAYS)
    newest_allowed = now + timedelta(days=1)
    qualifying = []
    states = {}
    finished_unreadable = 0
    finished_empty = 0
    finished_old = 0
    for job in jobs:
        if not isinstance(job, dict):
            continue
        state = " ".join(str(job.get("state") or "").lower().split())
        states[state or "(no state)"] = states.get(state or "(no state)", 0) + 1
        if state != "finished":
            continue
        finished = parse_utc(job.get("finishTime"))
        if finished is None:
            finished_unreadable = finished_unreadable + 1
            continue
        if finished < oldest or finished > newest_allowed:
            finished_old = finished_old + 1
            continue
        restored = successful_count(job)
        if restored is not None and restored < 1:
            finished_empty = finished_empty + 1
            continue
        qualifying.append({"id": str(job.get("id") or "")[:40], "finishTime": str(job.get("finishTime"))[:40]})
    summary = {"restoreJobsRead": len(jobs), "jobStates": states, "qualifyingRestores": len(qualifying),
               "finishedWithoutRestoredObjects": finished_empty, "finishedOutsideWindow": finished_old,
               "finishedWithUnreadableFinishTime": finished_unreadable, "windowDays": WINDOW_DAYS}
    if qualifying:
        latest = qualifying[0]
        for q in qualifying:
            if q["finishTime"] > latest["finishTime"]:
                latest = q
        return create_response({KEY: True, "qualifyingRestoreCount": len(qualifying),
                                "latestRestoreFinishedAt": latest["finishTime"]},
                               pass_reasons=[str(len(qualifying)) + " Cloud Backup for Microsoft 365 restore job(s) "
                                             "finished in the last " + str(WINDOW_DAYS) + " days; latest finished "
                                             + latest["finishTime"] + "."],
                               input_summary=summary)
    if finished_unreadable > 0:
        return not_evaluated(str(finished_unreadable) + " finished restore job(s) have no readable finishTime, so "
                             "whether a restore ran in the last " + str(WINDOW_DAYS) + " days is unknown.")
    if not jobs:
        reason = "AvePoint lists no restore job in the last " + str(WINDOW_DAYS) + " days."
    else:
        reason = ("None of the " + str(len(jobs)) + " restore job(s) read finished successfully in the last "
                  + str(WINDOW_DAYS) + " days (states: " + ", ".join(sorted([k + " " + str(states[k]) for k in states]))[:300]
                  + ").")
    return create_response({KEY: False, "qualifyingRestoreCount": 0}, fail_reasons=[reason],
                           recommendations=["Run and document a test restore in AvePoint Cloud Backup for Microsoft "
                                            "365 (for example restore a test file or mailbox item to an alternate "
                                            "location) at least once a year."],
                           input_summary=summary)


def transform(input):
    try:
        return measure(input)
    except Exception:
        return not_evaluated("the restore job response could not be processed")
