"""
Transformation: isUnifiedAuditLoggingEnabled
Vendor: Google Workspace  |  Category: Email Security

Criterion: the tenant's audit log is on and can be read. (isEquals true)

The key comes from Microsoft 365 ("unified audit log"). For Google Workspace it maps to the Workspace ADMIN
audit log (mapping confirmed by the product owner, 3 Oct 2026). Workspace records admin console activity
in that log for every edition and the log cannot be switched off, so the honest test is whether the log is
present and readable through the Admin SDK Reports API, and holds recorded admin events.

Data source: Admin SDK Reports API, one GET (IS method checkAuditLogs):
  GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin
  scope https://www.googleapis.com/auth/admin.reports.audit.readonly (domain-wide delegation).
Docs: https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
  Body: kind "admin#reports#activities", etag, items[] (kind "admin#reports#activity", id {time,
  uniqueQualifier, applicationName, customerId}, actor, events[]), nextPageToken. Newest event first; Google
  keeps about 180 days.

Verdict:
  True   the body is an admin#reports#activities feed whose items are all readable admin-application
         activity records with a timestamp, and at least one was returned. A nextPageToken only means more
         events exist; it does not weaken the proof.
  None   (Unevaluated, dataCollection error) error or scope body, None, {}, unrelated JSON, a feed of another
         application, a feed with unreadable records (partial), or an admin feed with no events at all (the log
         is readable but shows nothing recorded in Google's retention window).
  This key has no measured False: Workspace admin audit logging cannot be disabled, so a failed or empty read
  is Unevaluated, never a finding.

Does not prove: Gmail, Drive or login logging, export to a SIEM, or retention beyond Google's default.
"""
import json
from datetime import datetime

KEY = "isUnifiedAuditLoggingEnabled"
FEED_KIND = "admin#reports#activities"
ITEM_KIND = "admin#reports#activity"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
META = {"transformationId": KEY, "vendor": "Google Workspace", "category": "Email Security"}
SCOPE_HINTS = ["insufficient authentication scopes", "access_token_scope_insufficient", "unauthorized_client",
               "scope_not_granted", "access_denied", "request had insufficient authentication"]


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "_response_data"]
        for attempt in range(4):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict) and "kind" not in data:
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    metadata.update(META)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": metadata,
        },
    }


def unevaluated(problem, validation=None, summary=None, recommendation=None):
    return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem], api_errors=[problem],
                           input_summary=summary, recommendations=[recommendation] if recommendation else [])


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def error_in(data):
    """Google's or Integration-Service's error text when the body is an error envelope, else ''."""
    if not isinstance(data, dict):
        return ""
    for key in ["error", "errors", "errorMessage", "errorCode", "vendorAuthError"]:
        value = data.get(key)
        if value:
            if isinstance(value, dict):
                return " ".join([text(value.get(k)) for k in ["code", "status", "message"] if value.get(k)]) or text(value)[:200]
            return (text(value) + " " + text(data.get("message"))).strip()[:300]
    for key in ["statusCode", "status_code"]:
        code = data.get(key)
        if code is not None and text(code) != "200":
            return "HTTP " + text(code) + " " + text(data.get("message"))
    if text(data.get("status")).lower() == "error":
        return text(data.get("message")) or "Integration error"
    return ""


def explain_error(problem):
    low = problem.lower()
    for hint in SCOPE_HINTS:
        if hint in low:
            return ("Scope not granted: add " + REQUIRED_SCOPE + " to Spektrum's domain-wide delegation grant in the "
                    "Google Admin console. Google said: " + problem[:240])
    return "Google returned an error: " + problem[:300]


def parse_time(value):
    raw = text(value)
    if not raw:
        return None
    if len(raw) < 19 or raw[10] != "T":
        return None
    try:
        return datetime.fromisoformat(raw[:19])
    except ValueError:
        return None


def transform(input):
    try:
        if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
            input = None
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        if isinstance(input, str):
            input = json.loads(input)
        if input is None:
            return unevaluated("No response body; the admin audit log was not read.")
        data, validation = extract_input(input)
        problem = error_in(data)
        if problem:
            return unevaluated(explain_error(problem), validation,
                               recommendation="Check Spektrum's domain-wide delegation grant and re-evaluate")
        if not isinstance(data, dict) or text(data.get("kind")) != FEED_KIND:
            return unevaluated("The response is not a Reports API activity feed; the admin audit log cannot be "
                               "shown to have been read.", validation)
        items = data.get("items")
        if items is None:
            items = []
        if not isinstance(items, list):
            return unevaluated("The activity feed carries no readable items list.", validation)
        apps = {}
        bad = 0
        newest = None
        for item in items:
            ident = item.get("id") if isinstance(item, dict) and isinstance(item.get("id"), dict) else None
            when = parse_time(ident.get("time")) if ident is not None else None
            if ident is None or text(item.get("kind")) != ITEM_KIND or when is None:
                bad = bad + 1
                continue
            app = text(ident.get("applicationName")).lower() or "unknown"
            apps[app] = apps.get(app, 0) + 1
            if app == "admin" and (newest is None or when > newest):
                newest = when
        summary = {"items": len(items), "applications": apps, "unreadableItems": bad,
                   "newestAdminEvent": newest.isoformat() + "Z" if newest else None,
                   "morePages": bool(text(data.get("nextPageToken")))}
        if bad:
            return unevaluated(str(bad) + " of " + str(len(items)) + " activity records are unreadable; a partial "
                               "feed is not evaluated.", validation, summary)
        other = sorted([a for a in apps if a != "admin"])
        if other:
            return unevaluated("The feed holds " + "/".join(other) + " events, not admin audit events; it is not "
                               "the admin audit log.", validation, summary)
        if not items:
            return unevaluated("The admin audit log was read but holds no events in Google's retention window; it "
                               "cannot show admin activity is being recorded.", validation, summary)
        count = apps.get("admin", 0)
        return create_response(
            result={KEY: True, "adminAuditEventsRead": count}, validation=validation, input_summary=summary,
            pass_reasons=["Workspace admin audit logging is on and readable through the Reports API: "
                          + str(count) + " admin events read, newest " + newest.isoformat() + "Z"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
