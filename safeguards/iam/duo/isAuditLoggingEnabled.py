"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: iam
Evaluates: Confirms that audit logging is ACTIVE: the newest administrator log event returned by
/admin/v1/logs/administrator (getAdminLogs, mintime=1, limit=1000) is recent.

Rules (newest = the MAXIMUM timestamp over every entry, never the first one; `timestamp` epoch
seconds, else `isotimestamp`; entries with no valid timestamp, or more than 1 day in the future,
are ignored). Ages are measured against now_utc(), which tests replace.

  newest age <= 30 days                          -> True   (exactly 30 days is a PASS)
  30 < age <= 90 days                            -> Unevaluated (exactly 90 days is Unevaluated)
  age > 90 days, read complete (< 1000 entries)  -> False  ("no event in the last 90 days")
  age > 90 days, read at the 1000 limit          -> Unevaluated (newer events may be unread)
  empty list                                     -> Unevaluated (getAdminLogs' returnSpec defaults a
                                                    body it cannot read to [], so an empty list cannot
                                                    be told apart from a failed read; a Duo account
                                                    always logs its own administrator activity)
  error body, vendorErrorAsResponse, None, non-list, no usable timestamp, any exception
                                                 -> Unevaluated (value None), NEVER False
"""
import json
from datetime import datetime, timedelta, timezone

CRITERIA_KEY = "isAuditLoggingEnabled"
REQUEST_LIMIT = 1000  # getAdminLogs sends limit=1000: a list this long may be a cut window
FRESH_DAYS = 30
STALE_DAYS = 90
FUTURE_SLACK_SECONDS = 86400
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
RESULT_KEYS = ["totalLogCount", "wellFormedLogCount", "logsPresent", "mostRecentTimestamp",
               "newestEventAgeDays"]


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
        if (isinstance(stat, str) and stat.upper() == "FAIL") or "error" in data or (
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


def evaluate(data, now=None):
    """Returns {"state": "pass"|"fail"|"unevaluated", "reason": str, ...summary fields}."""
    reason = error_reason(data)
    if reason is not None:
        return {"state": "unevaluated", "reason": reason, "readError": True}
    entries = find_entries(data)
    if entries is None:
        return {"state": "unevaluated", "readError": True,
                "reason": "The response holds no administrator log list (expected a list from "
                          "/admin/v1/logs/administrator)"}
    if now is None:
        now = now_utc()
    now_epoch = (now - EPOCH).total_seconds()

    total = len(entries)
    well_formed = 0
    newest = None
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

    truncated = total >= REQUEST_LIMIT
    summary = {"totalLogCount": total, "wellFormedLogCount": well_formed,
               "logsPresent": total > 0, "mostRecentTimestamp": None, "newestEventAgeDays": None,
               "readMayBeTruncated": truncated}
    if total == 0:
        return dict(summary, state="unevaluated",
                    reason="The administrator log list is empty. An empty list cannot be told apart "
                           "from a read that returned nothing usable, so audit logging cannot be judged")
    if newest is None:
        return dict(summary, state="unevaluated",
                    reason="None of the " + str(total) + " administrator log entries carries a usable "
                           "timestamp, so recency cannot be judged")
    newest_dt = EPOCH + timedelta(seconds=newest)
    age_seconds = now_epoch - newest
    age_days = int(age_seconds // 86400) if age_seconds > 0 else 0
    summary["mostRecentTimestamp"] = newest_dt.isoformat()
    summary["newestEventAgeDays"] = age_days

    # Boundaries: exactly 30 days old is still fresh (PASS); exactly 90 days old is still
    # inside the "couldn't tell" band (Unevaluated), so only strictly older than 90 is a FAIL.
    if age_seconds <= FRESH_DAYS * 86400:
        return dict(summary, state="pass",
                    reason="Newest administrator log event is " + str(age_days) + " days old (within "
                           + str(FRESH_DAYS) + " days)")
    if truncated:
        return dict(summary, state="unevaluated",
                    reason="Newest administrator log event read is " + str(age_days) + " days old, but the "
                           "read returned " + str(total) + " entries (the request limit), so newer "
                           "events may not have been read")
    if age_seconds <= STALE_DAYS * 86400:
        return dict(summary, state="unevaluated",
                    reason="newest administrator log event is " + str(age_days) + " days old (more than "
                           + str(FRESH_DAYS) + ")")
    return dict(summary, state="fail",
                reason="no administrator log events in the last 90 days; newest is "
                       + str(age_days) + " days old")


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
        state = outcome["state"]
        if state == "unevaluated":
            return unevaluated_response(outcome["reason"], validation=validation,
                                        read_error=outcome.get("readError", False), summary=outcome)
        value = state == "pass"
        result = {CRITERIA_KEY: value}
        summary = {CRITERIA_KEY: value}
        for k in RESULT_KEYS:
            result[k] = outcome.get(k)
            summary[k] = outcome.get(k)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []
        if value:
            pass_reasons.append(outcome["reason"] + " -- " + str(outcome["totalLogCount"]) + " log entries read")
            pass_reasons.append(str(outcome["wellFormedLogCount"]) + " of " + str(outcome["totalLogCount"])
                                + " entries contain required fields (action, timestamp, username)")
            findings.append("Most recent log timestamp: " + str(outcome["mostRecentTimestamp"]))
        else:
            fail_reasons.append(outcome["reason"])
            recommendations.append("Verify that the Duo Admin API application has 'Grant read log' permission "
                                   "and that administrators are active in the Duo Admin Panel")
        return create_response(result=result, validation=validation, pass_reasons=pass_reasons,
                               fail_reasons=fail_reasons, recommendations=recommendations,
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
