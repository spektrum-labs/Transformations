"""
Transformation: isEmailSecurityLoggingEnabled
Vendor: Google Workspace
Category: Email Security

Evidence: getGmailLogEvents, the Admin SDK Reports API activity feed for applicationName=gmail
  GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/gmail
      ?startTime=<now-7d>&endTime=<now>
scope https://www.googleapis.com/auth/admin.reports.audit.readonly (Google requires both times
for Gmail, at most 30 days apart).

Rule (fail closed): true when the feed is a Gmail activity feed and returns at least one Gmail
log event dated within RECENT_DAYS. That proves Gmail log events are being recorded for the
tenant and are readable through the Reports API (the source a SIEM connector reads). False when
Gmail events were read and the newest is older than RECENT_DAYS: logging is not shown to be current.

Not measured (key None and dataCollection error, so Token-Service shows Not evaluated, never
Failed): an empty Gmail feed (either no mail flowed in the window or Gmail log events are not
available for the tenant's edition, so it cannot tell a missing control from a read that returned
nothing), Gmail events with no readable time, a Google error or refusal, a missing scope, a body
that is not JSON or not a Reports feed, and this transform's own exception. Admin audit events
(applicationName=admin, what this key read before) never pass: they show the admin console is
audited, not that email is logged, so that payload is not measured either.

Does not prove: that the logs are forwarded to a SIEM or retained beyond Google's defaults.
"""

import json
from datetime import datetime, timezone, timedelta


#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isEmailSecurityLoggingEnabled',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)

CRITERIA_KEY = "isEmailSecurityLoggingEnabled"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
RECENT_DAYS = 8


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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
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


SCOPE_HINTS = ["scope_not_granted", "access_denied", "unauthorized_client",
               "insufficient authentication scopes", "access_token_scope_insufficient",
               "request had insufficient authentication"]


def error_text(data):
    """Google's or Integration-Service's error text when the body is an error envelope, else ''."""
    if data is None:
        return "No response body"
    if isinstance(data, str):
        return "Empty response body" if data.strip() == "" else ""
    if not isinstance(data, dict):
        return ""
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return " ".join(str(x) for x in [value.get("code") or "", value.get("status") or "",
                                             value.get("message") or ""] if x) or str(value)
        parts = [str(x) for x in [data.get("message"), data.get("vendorAuthError"),
                                  data.get("error_description")] if x]
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


def vendor_error(data):
    """A clear reason when the body is an error, else None. A missing scope in the customer's
    domain-wide delegation grant is named as such, never read as a finding."""
    text = error_text(data)
    if not text:
        return None
    low = text.lower()
    if "missing_credentials" in low:
        return "Google Workspace admin email (subject) is not connected"
    for hint in SCOPE_HINTS:
        if hint in low:
            return ("scope not granted: add %s to Spektrum's domain-wide delegation grant "
                    "(client ID 117073617964097263607) in the Google Admin console. Google said: %s"
                    % (REQUIRED_SCOPE, text[:240]))
    if "service_disabled" in low or "has not been used in project" in low:
        return "Google API not enabled for Spektrum's service account project: %s" % text[:240]
    return text[:300]


def is_true(value):
    """Google bodies reach us with booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def parse_time(value):
    if value is None or str(value).strip() == "":
        return None
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def find_dict_with(data, key, depth=0):
    """The first dict (breadth-first through dict values, depth-limited) that has `key`."""
    frontier = [data]
    for level in range(5):
        next_frontier = []
        for node in frontier:
            if isinstance(node, dict):
                if key in node:
                    return node
                for value in node.values():
                    if isinstance(value, dict):
                        next_frontier.append(value)
        frontier = next_frontier
    return None


def not_measured(reason, validation, recommendation=None, result_extra=None):
    result = {CRITERIA_KEY: None}
    for k in (result_extra or {}):
        result[k] = result_extra[k]
    return create_response(
        result=result,
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        recommendations=[recommendation] if recommendation else []
    )


def is_truncated(body):
    """True when the feed still carries nextPageToken or the paginator marked the read as cut short."""
    if not isinstance(body, dict):
        return False
    marker = body.get("paginationTruncated")
    return bool(str(body.get("nextPageToken") or "").strip()) or marker is True or str(marker).strip().lower() == "true"


def transform(input):
    try:
        if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
            input = None
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if isinstance(data, dict) and "result" in data and isinstance(data.get("result"), dict):
            data = data["result"]

        error = vendor_error(data)
        if error is not None:
            return not_measured(error, validation, "Check Spektrum's domain-wide delegation grant and re-evaluate")
        if not (isinstance(data, dict) and str(data.get("kind", "")).startswith("admin#reports#")):
            return not_measured("response is not a Reports API activity feed", validation)

        items = data.get("items") if isinstance(data.get("items"), list) else []
        apps = {}
        newest = None
        gmail_events = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            ident = item.get("id") if isinstance(item.get("id"), dict) else {}
            app = str(ident.get("applicationName") or "").lower()
            apps[app] = apps.get(app, 0) + 1
            if app != "gmail":
                continue
            gmail_events = gmail_events + 1
            when = parse_time(ident.get("time"))
            if when is not None and (newest is None or when > newest):
                newest = when
        other = [a for a in apps if a != "gmail"]
        # A feed cut short holds only part of the events: the totals are None, never a partial count.
        cut_short = is_truncated(data)
        shown_events = None if cut_short else gmail_events
        newest_text = newest.isoformat() if newest else None
        if cut_short:
            summary = {"truncated": True, "newestGmailEvent": newest_text}
        else:
            summary = {"items": len(items), "applications": apps, "newestGmailEvent": newest_text}
        if other and gmail_events == 0:
            return not_measured(
                "the feed holds %s events, not Gmail log events; admin audit events do not prove email logging" % "/".join(sorted(other)),
                validation, "Re-point this check at the Reports API Gmail activity feed (getGmailLogEvents)")

        cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)
        result_value = newest is not None and newest >= cutoff
        if result_value:
            if cut_short:
                reads = "newest %s (the feed was cut short, so the count is not given)" % newest.isoformat()
            else:
                reads = "%d events read, newest %s" % (gmail_events, newest.isoformat())
            return create_response(result={CRITERIA_KEY: True, "gmailEventsRead": shown_events}, validation=validation,
                                   pass_reasons=["Gmail log events are recorded and readable: %s" % reads],
                                   input_summary=summary)
        # An empty feed, or events with no readable time, prove nothing either way: no mail may have
        # flowed in the window, or Gmail log events may not be offered for the edition. That is a read
        # that could not answer, not a finding.
        if gmail_events == 0:
            return not_measured("no Gmail log events were returned for the last 7 days", validation,
                                "Confirm Gmail log events are available for the tenant's Workspace edition and that mail is flowing")
        if newest is None:
            return not_measured("Gmail log events carry no readable timestamps (%d read)" % gmail_events, validation)
        if cut_short:
            # The pages not read could hold a recent event, so old events seen so far do not prove False.
            return not_measured("the Gmail log feed was cut short and the events read were older than %d days; "
                                "later pages could hold a recent one" % RECENT_DAYS, validation,
                                "Re-run the check so the whole feed is read")
        reason = "Newest Gmail log event is %s, older than %d days" % (newest.isoformat(), RECENT_DAYS)
        return create_response(result={CRITERIA_KEY: False, "gmailEventsRead": shown_events}, validation=validation,
                               fail_reasons=[reason],
                               recommendations=["Confirm Gmail log events are available for the tenant's Workspace edition and that mail is flowing"],
                               input_summary=summary)
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
