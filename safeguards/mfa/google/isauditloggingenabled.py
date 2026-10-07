"""
Transformation: isAuditLoggingEnabled
Vendor: Google Workspace (Admin SDK Reports API)
Category: Multifactor Authentication / Identity

Evidence: checkAuditLogs
  GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin
  scope https://www.googleapis.com/auth/admin.reports.audit.readonly
The Admin audit log feed, newest event first.

Rule (fail closed): true when the body is a Reports API activity feed of Admin audit events
(applicationName "admin") and the newest event is dated within RECENT_DAYS. That proves admin
activity is being recorded and is readable through the Reports API (the source a SIEM connector
reads). An empty feed, or one whose newest event is older than RECENT_DAYS, fails: logging is not
shown to be current. Admin audit logging cannot be switched off in Google Workspace, so a pass
here mostly proves the log is reachable and current, not a configuration choice.

A feed of other applications' events (for example Gmail or login) is not measured, and so is a
Google error, a missing scope or an unreadable body (key false, dataCollection error).
nextPageToken is ignored on purpose: the first page already holds the newest events.

Does not prove: that the logs are exported to a SIEM or retained beyond Google's defaults.
"""

import json
from datetime import datetime, timezone, timedelta

CRITERIA_KEY = "isAuditLoggingEnabled"
RECENT_DAYS = 90
REQUIRED_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for attempt in range(4):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": CRITERIA_KEY, "vendor": "Google Workspace",
                         "category": "Multifactor Authentication"}
        }
    }


def error_text(data):
    """Google's or Integration-Service's error text when the body is an error envelope, else ''."""
    if data is None:
        return "No response body"
    if isinstance(data, str):
        return "Empty response body" if data.strip() == "" else "Response body is not JSON"
    if not isinstance(data, dict):
        return ""
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return " ".join(str(x) for x in [value.get("code") or "", value.get("status") or "",
                                             value.get("message") or ""] if x) or str(value)
        parts = [str(x) for x in [data.get("message"), data.get("error_description")] if x]
        return " ".join(parts) if parts else str(value)
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s %s" % (code, data.get("message") or "")
    except (TypeError, ValueError):
        pass
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Integration error")
    return ""


def parse_time(value):
    if value is None or str(value).strip() == "":
        return None
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def not_measured(reason, validation, summary=None):
    return create_response(result={CRITERIA_KEY: False}, validation=validation, api_errors=[reason],
                           fail_reasons=["Not measured: " + reason], input_summary=summary or {})


def transform(input):
    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        data, validation = extract_input(input)

        error = error_text(data)
        if error:
            low = error.lower()
            if "scope" in low or "unauthorized_client" in low or "access_denied" in low:
                error = "scope not granted: %s is required. Google said: %s" % (REQUIRED_SCOPE, error[:240])
            return not_measured(error[:300], validation)
        if not (isinstance(data, dict) and str(data.get("kind", "")).startswith("admin#reports#")):
            return not_measured("response is not a Reports API activity feed", validation)

        items = data.get("items") if isinstance(data.get("items"), list) else []
        apps = {}
        newest = None
        admin_events = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            ident = item.get("id") if isinstance(item.get("id"), dict) else {}
            app = str(ident.get("applicationName") or "").lower()
            apps[app] = apps.get(app, 0) + 1
            if app != "admin":
                continue
            admin_events = admin_events + 1
            when = parse_time(ident.get("time"))
            if when is not None and (newest is None or when > newest):
                newest = when
        summary = {"items": len(items), "applications": apps, "newestAdminEvent": newest.isoformat() if newest else None}
        other = [a for a in apps if a != "admin"]
        if other and admin_events == 0:
            return not_measured("the feed holds %s events, not Admin audit events" % "/".join(sorted(other)),
                                validation, summary)

        cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)
        if newest is not None and newest >= cutoff:
            return create_response(result={CRITERIA_KEY: True, "adminEventsRead": admin_events}, validation=validation,
                                   pass_reasons=["Admin audit events are recorded and readable: %d read, newest %s"
                                                 % (admin_events, newest.isoformat())],
                                   input_summary=summary)
        if admin_events == 0:
            reason = "No Admin audit events were returned"
        elif newest is None:
            reason = "Admin audit events carry no timestamps (%d read)" % admin_events
        else:
            reason = "Newest Admin audit event is %s, older than %d days" % (newest.isoformat(), RECENT_DAYS)
        return create_response(result={CRITERIA_KEY: False, "adminEventsRead": admin_events}, validation=validation,
                               fail_reasons=[reason],
                               recommendations=["Confirm the Admin audit log is available for the tenant (Admin console > "
                                                "Reporting > Audit and investigation > Admin log events)"],
                               input_summary=summary)
    except Exception as e:
        return create_response(result={CRITERIA_KEY: False}, validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=["Transformation error: %s" % str(e)])
