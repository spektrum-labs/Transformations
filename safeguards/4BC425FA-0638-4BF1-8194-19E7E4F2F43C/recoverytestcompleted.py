"""
Transformation: recoveryTestCompleted
Vendor: AWS (RDS restores recorded by CloudTrail)
Category: Backups

Evidence: the isBackupTested workflow = CloudTrail LookupEvents for EventName
RestoreDBInstanceFromDBSnapshot (the same evidence isBackupTested reads).

Rule (fail closed): true when at least one restore event within WINDOW_DAYS completed WITHOUT an
errorCode in its CloudTrailEvent. Failed restore attempts do not count. CloudTrail LookupEvents
only holds 90 days, so in practice the window is 90 days.

Does not see: point-in-time restores (RestoreDBInstanceToPointInTime), AWS Backup restore jobs,
restores in other regions. A vendor error or unreadable body is reported as a data-collection
error (unevaluated), never as a pass.

This file previously held an Azure Recovery Services transform that read Azure-only fields.
"""

import json
from datetime import datetime, timezone, timedelta

CRITERIA_KEY = "recoveryTestCompleted"
WINDOW_DAYS = 365


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
                "transformationId": CRITERIA_KEY,
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


def vendor_error(data):
    """The vendor's own error message when the body is an error envelope, else None."""
    if data is None:
        return "No response body"
    if not isinstance(data, dict):
        return None
    for key in ["error", "errors", "Error", "ErrorResponse", "__type", "errorType", "errorCode"]:
        value = data.get(key)
        if value:
            if isinstance(value, dict):
                inner = value.get("Error") if isinstance(value.get("Error"), dict) else value
                return str(inner.get("Message") or inner.get("message") or inner.get("Code") or value)
            return "%s: %s" % (value, data.get("Message") or data.get("message") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    return None


def as_list(value):
    """XML-derived bodies give a dict for one item, a list for several, and 'None' for zero."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def dig(data, path):
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def parse_time(value):
    if value is None or str(value).strip() in ("", "None"):
        return None
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def to_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def automated_backups(data):
    """(list of automated backups, error message or None) from the workflow or a bare response."""
    section = data.get("dbBackups") if isinstance(data, dict) and "dbBackups" in data else data
    error = vendor_error(section)
    if error is not None:
        return None, error
    response = section.get("DescribeDBInstanceAutomatedBackupsResponse") if isinstance(section, dict) else None
    if not isinstance(response, dict):
        return None, "Response has no DescribeDBInstanceAutomatedBackupsResponse; RDS automated backups were not read"
    items = dig(response, ["DescribeDBInstanceAutomatedBackupsResult", "DBInstanceAutomatedBackups", "DBInstanceAutomatedBackup"])
    return as_list(items), None


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        error = vendor_error(data)
        response = data.get("LookupEventsResponse") if isinstance(data, dict) else None
        if error is None and not isinstance(response, dict):
            error = "Response has no LookupEventsResponse; CloudTrail restore events were not read"
        if error is not None:
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                api_errors=[error],
                fail_reasons=["Not measured: " + error]
            )

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=WINDOW_DAYS)
        events = as_list(dig(response, ["LookupEventsResult", "Events", "member"]))
        succeeded = []
        failed = []
        for event in events:
            when = parse_time(event.get("EventTime"))
            detail = event.get("CloudTrailEvent")
            if isinstance(detail, str):
                try:
                    detail = json.loads(detail)
                except ValueError:
                    detail = {}
            if not isinstance(detail, dict):
                detail = {}
            label = "%s at %s" % (event.get("EventName"), event.get("EventTime"))
            if detail.get("errorCode"):
                failed.append("%s failed: %s" % (label, detail.get("errorCode")))
            elif when is not None and when >= cutoff:
                succeeded.append(label)

        result_value = len(succeeded) > 0
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("%d successful RDS snapshot restore(s) in the lookup window; newest listed: %s" % (len(succeeded), succeeded[0]))
        else:
            fail_reasons.append("No successful RDS snapshot restore in CloudTrail (%d events, %d failed)" % (len(events), len(failed)))
            recommendations.append("Run and record a restore test from a backup snapshot")

        return create_response(
            result={CRITERIA_KEY: result_value, "successfulRestores": len(succeeded), "failedRestores": len(failed)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=[{"metric": "failedRestore", "value": False, "reason": f} for f in failed],
            input_summary={"events": len(events), "successful": len(succeeded), "failed": len(failed)}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
