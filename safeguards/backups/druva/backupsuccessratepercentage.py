"""
Transformation: backupSuccessRatePercentage
Vendor: Druva (Data Security Cloud, Enterprise Workloads)  |  Category: Backups
Method: getBackupActivity -> POST /platform/reporting/v1/reports/ewBackupActivity
Evaluates: Percentage of Druva backup sets whose latest finished job in the Backup Activity report is Successful or Successful with errors. The read window is the one the integration definition sets (7 days today: lastUpdatedTime GTE utcNow-7d). Queued/Running jobs are excluded; earlier jobs superseded by a later run on the same set do not count.
Unevaluated (None, dataCollection.status "error"): zero jobs in the window, only in-flight jobs, a partial read, a missing, error or unrecognised body, failed input validation, or a transformation error.
"""
import json
from datetime import datetime, timedelta

CRITERIA_KEY = "backupSuccessRatePercentage"
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
# (the definition's read window, 7 days today) is empty by construction, even when every backup
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
    """Timestamp to the second, in UTC: a trailing +hh:mm/-hh:mm (or +hhmm) offset is applied; Z, none or anything else is read as UTC.
    strptime is not usable: it imports a module the sandbox refuses."""
    value = text(value)
    try:
        when = datetime.fromisoformat(value[:19]) if len(value) >= 19 else None
    except ValueError:
        return None
    if when is None:
        return None
    rest = value[19:]
    if rest.startswith("."):
        rest = rest.lstrip(".0123456789")
    digits = rest[1:].replace(":", "")
    if rest[:1] in ("+", "-") and len(digits) == 4 and digits.isdigit():
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        try:
            when = when - offset if rest[0] == "+" else when + offset
        except OverflowError:  # pushed past year 1 or 9999: this row is untimed, the read is not lost
            return None
    return when


# A job that has not finished yet is in neither the numerator nor the denominator.
# Not yet finished: excluded from both sides. Matched as prefixes ("Queued (2)", "Running - 40%"), with "waiting" exact.
# Waiting for retry, Paused and Resuming are not here on purpose: they follow a failed or stopped attempt, so they
# score as not passing rather than letting an older success decide the set.
IN_FLIGHT = ("queued", "running", "in progress", "scheduled", "pending", "starting")
# "Successful with errors" passes: the job finished and protected the set; Druva uses it when only some files were skipped.
PASSING = ("successful", "successful with errors")
TIME_FIELDS = ("started", "scheduled", "lastUpdatedTime")


def status_of(row):
    return text(row.get("status")).lower()


def is_in_flight(row):
    status = status_of(row)
    return status == "waiting" or status.startswith(IN_FLIGHT)


def set_key(row, index):
    """A backup set's identity. jobID sequences differ per workload, so a set is the tuple of its descriptors.
    A row with no real backupSet has no reliable identity, so it stands alone (keyed on its row index).
    deviceName and vm are "NA" on real file-server and VM rows alike, so a host cannot be required. The host is carried by backupSet (file-server sets, e.g. "<server>-data") and by
    configurationMode for VMs (e.g. "<vcenter>:<datacenter>"). Two hosts sharing every descriptor would merge (accepted)."""
    backup_set = text(row.get("backupSet"))
    if backup_set == "" or backup_set.upper() == "NA":
        return ("unidentified", index)
    return tuple(text(row.get(f)) for f in ("organization", "administrativeGroup", "backupSet", "deviceName",
                                             "vm", "resourceType", "configurationMode"))


def latest_per_set(finished):
    """Each backup set's newest finished job, so a failure a later retry fixed is not still counted.
    A set's timed rows are all ranked on one time field, the first of started/scheduled/lastUpdatedTime that every timed row carries,
    so two kinds of time are never compared. A row with no parseable time ranks below every timed row. With no shared field, jobID
    decides; on a full tie a failing job outranks a passing one."""
    sets = {}
    for index, row in enumerate(finished):
        sets.setdefault(set_key(row, index), []).append(row)
    latest = []
    for rows in sets.values():
        timed = [r for r in rows if any(parse_time(r.get(f)) for f in TIME_FIELDS)]
        field = None
        for candidate in TIME_FIELDS:
            if timed and all(parse_time(r.get(candidate)) for r in timed):
                field = candidate
                break
        best = None
        for row in rows:
            when = (parse_time(row.get(field)) if field else None) or datetime.min
            try:
                job_num = int(text(row.get("jobID")))
            except ValueError:  # missing, "NA", "abc", "²": no usable id
                job_num = -1
            has_time = any(parse_time(row.get(f)) for f in TIME_FIELDS)
            rank = (1 if has_time else 0, when, job_num, 0 if status_of(row) in PASSING else 1)
            if best is None or rank > best[0]:
                best = (rank, row)
        latest.append(best[1])
    return latest


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
        value, summary, reasons = evaluate(jobs, meta["partial"], meta, len(records))
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


def evaluate(jobs, partial, meta, reported):
    """Score each backup set by its latest finished job: Successful and Successful with errors pass, anything else fails."""
    in_flight = [r for r in jobs if is_in_flight(r)]
    finished = [r for r in jobs if not is_in_flight(r)]
    latest = latest_per_set(finished)
    summary = {"backupJobsReported": reported, "backupRowsIgnored": reported - len(jobs), "backupJobsInFlight": len(in_flight),
               "backupJobsSuperseded": len(finished) - len(latest), "backupSetsEvaluated": len(latest)}
    if meta.get("windowStart"):
        summary["windowStart"] = meta["windowStart"]
    summary["partialRead"] = partial
    if partial:
        return None, summary, ["The Druva Backup Activity read is partial (more pages were not read), so it cannot answer this; nothing was concluded"]
    if len(latest) == 0:
        return None, summary, ["All " + str(len(jobs)) + " Druva backup jobs read are still in flight (queued or running), so no finished job was measured"]
    tail = ("; " + str(len(in_flight)) + " in-flight jobs excluded, " + str(len(finished) - len(latest))
            + " earlier jobs superseded by a later run" + (" (read since " + meta["windowStart"] + ")" if meta.get("windowStart") else ""))
    ok = [r for r in latest if status_of(r) in PASSING]
    summary["backupSetsSuccessful"] = len(ok)
    rate = round(len(ok) * 100.0 / len(latest), 2)
    return rate, summary, [str(len(ok)) + " of " + str(len(latest)) + " Druva backup sets' latest finished job was Successful (" + str(rate) + "%)" + tail]
