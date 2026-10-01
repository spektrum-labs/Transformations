"""
Transformation: failedBackupJobsCount
Vendor: Druva (Data Security Cloud, Enterprise Workloads)  |  Category: Backups
Method: getBackupActivity -> POST /platform/reporting/v1/reports/ewBackupActivity
Evaluates: Count of jobs in the Druva Backup Activity report (the read window the definition sets; Druva's default is the last 24 hours) whose status is not Successful. Only Successful is a documented status value, so every other status counts as failed.
Unevaluated (None, dataCollection.status "error"): zero jobs in the window, a partial read, a missing, error or unrecognised body, failed input validation, or a transformation error.
"""
import json
from datetime import datetime

CRITERIA_KEY = "failedBackupJobsCount"
RECOMMENDATION = "Investigate the Druva backup jobs that did not complete successfully."


WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output"]


def extract_input(input_data):
    """Decode the body and unwrap Spektrum envelopes. Undecodable input raises; transform() catches it and returns Unevaluated."""
    data = input_data
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    if isinstance(data, str):
        data = json.loads(data)
    if isinstance(data, dict) and "validation" in data and "data" in data and isinstance(data.get("validation"), dict):
        return data["data"], data["validation"]
    if isinstance(data, dict):
        for depth in range(3):
            unwrapped = False
            for key in WRAPPER_KEYS:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": []}


def report_records(data):
    """Rows of a Druva Reports API response (POST /platform/reporting/v1/reports/{reportID}).

    Documented envelope: {"data": [...], "lastSyncTimestamp": "...", "filters": {...},
    "nextPageToken": "..."}. Anything else (error envelope, null, unrelated JSON) returns
    None, which every caller treats as NO EVIDENCE.

    This is a legacy-format transform, so Token-Service drills the envelope
    (response -> result -> apiResponse -> Output -> data) before calling it: the body
    normally arrives as the bare "data" row list. Accept that drilled list, and the
    undrilled envelope too.
    """
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if not isinstance(data, dict):
        return None
    rows = data.get("data")
    if not isinstance(rows, list):
        return None
    if "lastSyncTimestamp" not in data:
        return None
    return [r for r in rows if isinstance(r, dict)]


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": CRITERIA_KEY, "vendor": "Druva", "category": "Backups"}
        }
    }


# ---- Unevaluated, not a finding (2026-10-01) ------------------------------------------------
# A read that measured nothing returns the key as None with dataCollection.status "error".
# Token-Service reads that as Unevaluated: grey, out of the score denominator, never a pass and
# never a finding. That covers a missing, null, error or unrecognised body, failed input
# validation, a transformation exception, a partial (truncated) read that cannot answer, and a
# Backup Activity read with ZERO jobs.
#
# Why zero jobs is not a finding: the report only holds jobs that Druva's reporting store has
# synced, and the store syncs about once a day. A read whose window starts after the last sync
# (Druva's default window is the last 24 hours) is empty by construction, even when every backup
# set is enabled and the last nightly run was all Successful. The backup-set count is a different
# report (ewResourceStatus), so this read cannot tell "no jobs because nothing is protected" from
# "no jobs because the report has not synced yet". Only a body that lists jobs is a measurement.
def error_problem(data):
    """Describe why `data` is a vendor or platform error rather than evidence, or return None."""
    if data is None:
        return "Druva returned no body"
    if isinstance(data, (str, bytes)):
        return "Druva returned a body that is not JSON"
    if not isinstance(data, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus", "vendorStatus", "code"):
        code = data.get(name)
        if isinstance(code, str) and code.isdigit():
            code = int(code)
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Druva returned HTTP " + str(code)
    err = data.get("error") or data.get("vendorError") or data.get("errorCode")
    if err:
        if isinstance(err, dict):
            err = err.get("message") or err.get("code") or "error"
        return "Druva returned an error: " + str(err)[:200]
    if str(data.get("status", "")).lower() == "error":
        return "the integration reported an error status"
    return None


def unevaluated(problem, validation=None, input_summary=None, transformation_errors=None):
    """The key as None plus a dataCollection error: reads Unevaluated, never True and never False."""
    return create_response(
        {CRITERIA_KEY: None}, validation,
        fail_reasons=[problem],
        api_errors=[problem],
        input_summary=input_summary,
        transformation_errors=transformation_errors)


def job_rows(records):
    """The rows that look like Backup Activity jobs. Every ewBackupActivity row carries a status;
    a list with none is not this report, so it is not read as one."""
    return [r for r in records if "status" in r]


def read_window(data):
    """What the undrilled envelope says about the read: its window start, last sync and completeness.

    Token-Service normally drills the envelope to the bare row list, and then none of this is
    known; the drilled list is read as a complete page set (Integration-Service follows the
    cursor). When the envelope does arrive, an unread nextPageToken or a truncated flag marks
    the read partial.
    """
    meta = {"partial": False}
    if not isinstance(data, dict):
        return meta
    if text(data.get("lastSyncTimestamp")):
        meta["lastSyncTimestamp"] = text(data.get("lastSyncTimestamp"))[:40]
    filters = data.get("filters")
    if isinstance(filters, dict) and isinstance(filters.get("filterBy"), list):
        for rule in filters.get("filterBy"):
            if not isinstance(rule, dict):
                continue
            column = text(rule.get("columnName") or rule.get("fieldName"))
            if column == "lastUpdatedTime" and text(rule.get("operator")).upper() == "GTE":
                meta["windowStart"] = text(rule.get("value"))[:40]
    if text(data.get("nextPageToken")):
        meta["partial"] = True
    for flag in ("paginationTruncated", "truncated"):
        if str(data.get(flag, "")).lower() == "true":
            meta["partial"] = True
    return meta


def parse_time(value):
    """UTC timestamp to the second. strptime is not usable: it imports a module the sandbox refuses."""
    value = text(value)[:19]
    if len(value) != 19:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def empty_read_problem(meta):
    reason = ("Druva Backup Activity report returned no jobs in its window. Zero jobs is not a measurement: "
              "the report holds only jobs Druva has synced, and the backup-set count is not part of this read, "
              "so this is not a finding")
    synced = parse_time(meta.get("lastSyncTimestamp"))
    start = parse_time(meta.get("windowStart"))
    if synced is not None and start is not None and synced < start:
        reason = (reason + ". Druva's report data last synced at " + meta.get("lastSyncTimestamp")
                  + ", before the read window started at " + meta.get("windowStart")
                  + ", so the window was empty by construction")
    return reason


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return unevaluated("Input validation failed; nothing was measured", validation)
        problem = error_problem(data)
        if problem:
            return unevaluated(problem, validation)
        records = report_records(data)
        if records is None:
            return unevaluated(
                "Response is not a Druva Reports API envelope (data + lastSyncTimestamp) or its row list; nothing was measured",
                validation)
        meta = read_window(data)
        if len(records) == 0:
            return unevaluated(empty_read_problem(meta), validation,
                               input_summary={"backupJobsReported": 0, **meta})
        jobs = job_rows(records)
        if len(jobs) == 0:
            return unevaluated(
                "None of the " + str(len(records)) + " rows is a Druva Backup Activity job (no status field); nothing was measured",
                validation, input_summary={"rowsReported": len(records)})
        value, summary, reasons = evaluate(records, meta["partial"])
        if value is None:
            return unevaluated(reasons[0], validation, input_summary=summary)
        passed = value is not False
        return create_response(
            {CRITERIA_KEY: value, **summary}, validation,
            pass_reasons=reasons if passed else [],
            fail_reasons=[] if passed else reasons,
            recommendations=[] if passed else [RECOMMENDATION],
            input_summary=summary)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), None, transformation_errors=[str(e)])


def evaluate(records, partial):
    bad = [r for r in records if text(r.get("status")).lower() != "successful"]
    statuses = {}
    for r in bad:
        s = text(r.get("status")) or "missing"
        statuses[s] = statuses.get(s, 0) + 1
    summary = {"backupJobsReported": len(records), "nonSuccessfulStatuses": statuses, "partialRead": partial}
    if partial:
        return None, summary, ["The Druva Backup Activity read is partial (more pages were not read), so it cannot answer this; nothing was concluded"]
    return len(bad), summary, [str(len(bad)) + " of " + str(len(records)) + " Druva backup jobs did not report Successful"]
