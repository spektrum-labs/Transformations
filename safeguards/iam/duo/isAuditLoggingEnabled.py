"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: iam
Evaluates: Duo's administrator audit log can be read through the Admin API.

Source: GET /admin/v1/logs/administrator (method getAdminLogs). The method sends
mintime = now - 30 days, in epoch seconds ({$utcNowS-30d}), so Duo returns administrator
events from the last 30 days only. Duo v1 returns this log OLDEST first, at most 1000 events
per call, and pages it by mintime rather than by an offset. A read that comes back with 1000
events therefore holds the earliest 1000 events of the window, and newer events may exist that
were not read.

Why a readable log is a pass, empty or not. Duo records administrator actions for every
account and gives no setting to turn that off. An empty 30-day window means no administrator
made a change in that window, not that logging stopped, so there is nothing for the customer
to fix in Duo and an empty window is never a finding.

Rules:
  log list read, empty or not                                  -> True
  Duo error body, vendorErrorAsResponse marker, an Integration-Service error envelope,
  a body with no log list, a non-empty list in which no event carries a usable timestamp,
  None, non-JSON, any exception                                -> Not evaluated (value None)
  never False.

Evidence: the window (last 30 days), the number of events read, the oldest and newest event
times read, and readMayBeTruncated. When the read hit the 1000-event limit, the newest event
read is NOT the newest administrator event in the window, and the evidence says so.
"""
import json
from datetime import datetime, timedelta, timezone

CRITERIA_KEY = "isAuditLoggingEnabled"
REQUEST_LIMIT = 1000  # Duo v1 returns at most the earliest 1000 events from mintime
WINDOW_DAYS = 30  # getAdminLogs sends mintime = now - 30 days
FUTURE_SLACK_SECONDS = 86400
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
ENDPOINT = "/admin/v1/logs/administrator"
RESULT_KEYS = ["totalLogCount", "wellFormedLogCount", "logsPresent", "mostRecentTimestamp",
               "oldestTimestamp", "newestEventAgeDays", "windowDays", "readMayBeTruncated"]


def now_utc():
    """Current time; a module-level function so tests can substitute a fixed clock."""
    return datetime.now(timezone.utc)


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isAuditLoggingEnabled",
                "vendor": "Duo",
                "category": "iam"
            }
        }
    }


def has_required_fields(log_entry):
    has_action = "action" in log_entry and log_entry["action"] is not None
    has_timestamp = ("timestamp" in log_entry or "isotimestamp" in log_entry) and (
        log_entry.get("timestamp") is not None or log_entry.get("isotimestamp") is not None
    )
    has_username = "username" in log_entry and log_entry["username"] is not None
    return has_action and has_timestamp and has_username


def entry_epoch(entry):
    """Epoch seconds of one log entry, or None when it has no valid timestamp."""
    ts = entry.get("timestamp")
    if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts > 0:
        return float(ts)
    iso = entry.get("isotimestamp")
    if isinstance(iso, str) and iso.strip():
        text = iso.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return (parsed - EPOCH).total_seconds()
        except (ValueError, OverflowError, TypeError):
            return None
    return None


def error_reason(data):
    """Why this body is not a log list (an error or marker envelope), else None."""
    if isinstance(data, dict):
        if "vendorErrorAsResponse" in data:
            return "Duo returned an error instead of administrator log data: " + str(
                data.get("vendorErrorAsResponse"))[:300]
        stat = data.get("stat")
        status = data.get("status")
        if (isinstance(stat, str) and stat.upper() == "FAIL") or data.get("error") not in (None, False) or (
                "errorMessage" in data) or (isinstance(status, str) and status.lower() == "error") or (
                "code" in data and "message" in data):
            return "Duo returned an error body instead of administrator log data: " + str(data)[:300]
    return None


def find_entries(data):
    """The administrator log list inside the body, or None when there is none."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for candidate_key in ["response", "logs", "admin_logs", "events"]:
            candidate = data.get(candidate_key)
            if isinstance(candidate, list):
                return candidate
    return None


def iso_of(epoch_seconds):
    return (EPOCH + timedelta(seconds=epoch_seconds)).isoformat()


def evaluate(data, now=None):
    """Returns {"state": "pass"|"unevaluated", "reason": str, ...summary fields}. Never "fail"."""
    reason = error_reason(data)
    if reason is not None:
        return {"state": "unevaluated", "reason": reason, "readError": True}
    entries = find_entries(data)
    if entries is None:
        return {"state": "unevaluated", "readError": True,
                "reason": "The response holds no administrator log list (expected a list from "
                          + ENDPOINT + ")"}
    if now is None:
        now = now_utc()
    now_epoch = (now - EPOCH).total_seconds()
    window_start = now - timedelta(days=WINDOW_DAYS)

    total = len(entries)
    well_formed = 0
    newest = None
    oldest = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if has_required_fields(entry):
            well_formed = well_formed + 1
        ts = entry_epoch(entry)
        if ts is None or ts > now_epoch + FUTURE_SLACK_SECONDS:
            continue  # no valid timestamp, or implausibly in the future: never evidence
        if newest is None or ts > newest:
            newest = ts
        if oldest is None or ts < oldest:
            oldest = ts

    truncated = total >= REQUEST_LIMIT
    window_text = ("the last " + str(WINDOW_DAYS) + " days (events since about "
                   + window_start.date().isoformat() + ")")
    summary = {"totalLogCount": total, "wellFormedLogCount": well_formed,
               "logsPresent": total > 0, "mostRecentTimestamp": None, "oldestTimestamp": None,
               "newestEventAgeDays": None, "windowDays": WINDOW_DAYS,
               "readMayBeTruncated": truncated, "window": window_text}
    if total == 0:
        return dict(summary, state="pass",
                    reason="Duo returned the administrator log (" + ENDPOINT + ") for " + window_text
                           + " and it holds no events: no administrator made a change in that window. "
                           "Duo records administrator actions for every account and has no setting "
                           "to turn this off, so an empty window is not a gap")
    if newest is None:
        return dict(summary, state="unevaluated", readError=True,
                    reason="None of the " + str(total) + " administrator log entries carries a usable "
                           "timestamp, so the response cannot be read as an administrator log")
    age_seconds = now_epoch - newest
    age_days = int(age_seconds // 86400) if age_seconds > 0 else 0
    summary["mostRecentTimestamp"] = iso_of(newest)
    summary["oldestTimestamp"] = iso_of(oldest)
    summary["newestEventAgeDays"] = age_days

    if truncated:
        return dict(summary, state="pass",
                    reason="Duo returned " + str(total) + " administrator log events (" + ENDPOINT
                           + ") for " + window_text + ", from " + summary["oldestTimestamp"] + " to "
                           + summary["mostRecentTimestamp"] + ". That is Duo's per-call limit, and Duo "
                           "returns this log oldest first, so these are the earliest " + str(total)
                           + " events of the window: newer events may exist that were not read, and the "
                           "latest administrator event may be more recent than " + summary["mostRecentTimestamp"])
    return dict(summary, state="pass",
                reason="Duo returned " + str(total) + " administrator log events (" + ENDPOINT + ") for "
                       + window_text + ", from " + summary["oldestTimestamp"] + " to "
                       + summary["mostRecentTimestamp"] + ". The latest administrator event is "
                       + summary["mostRecentTimestamp"] + " (" + str(age_days) + " days ago)")


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return unevaluated_response("Input validation failed; the log list is not evidence",
                                        validation=validation, read_error=True)
        outcome = evaluate(data, now_utc())
        if outcome["state"] != "pass":
            return unevaluated_response(outcome["reason"], validation=validation,
                                        read_error=outcome.get("readError", False), summary=outcome)
        result = {CRITERIA_KEY: True}
        summary = {CRITERIA_KEY: True}
        for k in RESULT_KEYS:
            result[k] = outcome.get(k)
            summary[k] = outcome.get(k)
        pass_reasons = [outcome["reason"]]
        findings = ["Window read: " + outcome["window"]]
        if outcome["totalLogCount"] > 0:
            pass_reasons.append(str(outcome["wellFormedLogCount"]) + " of " + str(outcome["totalLogCount"])
                                + " entries contain the administrator log fields (action, timestamp, username)")
            if outcome["readMayBeTruncated"]:
                findings.append("Newest event read: " + str(outcome["mostRecentTimestamp"])
                                + " (not the newest in the window: the read stopped at Duo's "
                                + str(REQUEST_LIMIT) + "-event limit)")
            else:
                findings.append("Latest administrator event: " + str(outcome["mostRecentTimestamp"]))
        return create_response(result=result, validation=validation, pass_reasons=pass_reasons,
                               input_summary=summary, additional_findings=findings)
    except Exception as e:
        return unevaluated_response("Transformation error: " + str(e), transformation_errors=[str(e)])


def unevaluated_response(reason, validation=None, read_error=False, summary=None, transformation_errors=None):
    """Not evaluated: every value None. Never False, because nothing was measured."""
    result = {CRITERIA_KEY: None}
    for k in RESULT_KEYS:
        result[k] = None
    response = create_response(
        result=result,
        validation=validation if validation is not None else {"status": "unknown", "errors": [], "warnings": []},
        fail_reasons=[reason],
        recommendations=["Re-run once Duo returns the administrator log list; confirm the Admin API "
                         "application has 'Grant read log' permission"],
        input_summary={k: (summary or {}).get(k) for k in RESULT_KEYS} if summary else {},
        api_errors=[reason],
        transformation_errors=transformation_errors,
    )
    return response
