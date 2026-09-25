"""
Transformation: isEmailLoggingEnabled
Vendor: Google Workspace
Category: Email Security

Evidence: checkAuditLogs, the Admin SDK Reports API activity feed for applicationName=admin (the
same call isEmailSecurityLoggingEnabled reads).

Google Workspace audit logging cannot be switched off, so the question this can answer is whether
the audit log is recording and readable NOW. Rule (fail closed): true when the feed returns at
least one event dated within RECENT_DAYS. An empty feed, a stale feed, or events without
timestamps fail. A Google error or unreadable body is reported as a data-collection error
(unevaluated), never as a pass. The count of EMAIL_SETTINGS events (Gmail configuration changes)
is reported alongside.

PROXY: this is the admin audit log, not Gmail message logs. Proving Gmail log events (message
delivery, spam and phishing verdicts) needs the Gmail log BigQuery export or a Reports API call
for Gmail activity, which this integration does not make.
"""

import json
from datetime import datetime, timezone, timedelta

CRITERIA_KEY = "isEmailLoggingEnabled"
RECENT_DAYS = 30


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
                "vendor": "Google Workspace",
                "category": "Email Security"
            }
        }
    }


def vendor_error(data):
    """Google's own error message when the body is an error envelope, else None."""
    if data is None:
        return "No response body"
    if isinstance(data, str) and data.strip() == "":
        return "Empty response body"
    if not isinstance(data, dict):
        return None
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return str(value.get("message") or value.get("status") or value.get("code") or value)
        return "%s %s" % (value, data.get("message") or data.get("error_description") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    return None


def is_true(value):
    """Cloud Identity returns booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def parse_time(value):
    if value is None or str(value).strip() == "":
        return None
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        error = vendor_error(data)
        if error is None and not (isinstance(data, dict) and str(data.get("kind", "")).startswith("admin#reports#")):
            error = "Response is not a Reports API activity feed"
        if error is not None:
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                api_errors=[error],
                fail_reasons=["Not measured: " + error]
            )

        items = data.get("items") if isinstance(data.get("items"), list) else []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=RECENT_DAYS)
        newest = None
        email_events = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            ident = item.get("id") if isinstance(item.get("id"), dict) else {}
            when = parse_time(ident.get("time"))
            if when is not None and (newest is None or when > newest):
                newest = when
            for event in item.get("events") or []:
                if isinstance(event, dict) and event.get("type") == "EMAIL_SETTINGS":
                    email_events = email_events + 1

        result_value = newest is not None and newest >= cutoff
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Admin audit log is recording: %d events read, newest %s (%d EMAIL_SETTINGS events)" % (
                len(items), newest.isoformat(), email_events))
        elif newest is None:
            fail_reasons.append("Admin audit feed returned no dated events (%d items)" % len(items))
            recommendations.append("Confirm the service account has admin.reports.audit.readonly and the tenant has audit data")
        else:
            fail_reasons.append("Newest admin audit event is %s, older than %d days" % (newest.isoformat(), RECENT_DAYS))
            recommendations.append("Check why the Workspace audit log has no recent events")

        return create_response(
            result={CRITERIA_KEY: result_value, "auditEventsRead": len(items), "emailSettingsEvents": email_events},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"items": len(items), "newestEvent": newest.isoformat() if newest else None}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
