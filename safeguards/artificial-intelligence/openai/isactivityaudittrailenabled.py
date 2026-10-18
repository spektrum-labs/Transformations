"""
Transformation: isActivityAuditTrailEnabled
Vendor: OpenAI  |  Category: Artificial Intelligence
Product: OpenAI API (API Platform)
Evaluates: The organization audit log is enabled and readable: GET /v1/organization/audit_logs returns at least one event.
A list with events proves logging is on (OpenAI cannot switch it off once enabled). An empty list proves nothing:
the Administration API exposes no setting that says whether audit logging is on (the public OpenAPI spec has
only the list endpoint), so "off" and "on but quiet" look the same. An empty list is reported as not evaluated
(None with a dataCollection error), never as False.
API Source: listAuditLogs (GET /v1/organization/audit_logs?limit=1)
Credential: Admin API key (sk-admin-...). Endpoints confirmed in the OpenAI OpenAPI spec
(github.com/openai/openai-openapi, security AdminApiKeyAuth).
Not evaluated, never False: the API has no field that says audit logging is off, so the only
readable answer is events (True). A refused call (401/403/404/429), an unrecognised body, an
empty log and an exception inside this file answer None with dataCollection.status "error",
which Token-Service records as not evaluated. An empty log cannot tell "logging is off" from
"logging is on and nothing has been logged yet": audit logging is an opt-in organization setting
(help.openai.com/en/articles/9687866), and the API reference documents no response that means
"not activated" (openai-openapi: 200, 400, 404 for a bad cursor, 429).
"""
import json
from datetime import datetime, timezone

KEY = "isActivityAuditTrailEnabled"


def extract_input(raw):
    """Return (data, validation) from the enriched, wrapped, string or bare input.

    Token-Service hands this file the enriched form {"data": <raw response>, "validation": ...}
    because the evaluate() below reads input.get("data"). That keeps the OpenAI list
    envelope (has_more) and the workflow siblings (projectApiKeys, orgDataRetention) intact;
    the legacy drill into "data" would drop both. A string that is not JSON raises into
    transform()'s handler: fail closed.
    """
    if isinstance(raw, (str, bytes)):
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        raw = json.loads(raw)
    if isinstance(raw, dict) and "data" in raw and "validation" in raw:
        return raw["data"], raw["validation"]
    data = raw
    if isinstance(data, dict):
        for attempt in range(3):
            unwrapped = False
            for key in ("api_response", "response", "result", "apiResponse", "Output"):
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    additional_findings=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    errors = transformation_errors or []
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if errors else "success",
                "errors": errors,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "OpenAI",
                "category": "Artificial Intelligence",
            },
        },
    }


# A refused call is not a posture finding: the control's state is unknown, so the key is
# None (not evaluated) with the reason, never true and never false. OpenAI documents:
# "Admin API keys cannot be used for non-administration endpoints"; the reverse holds
# too - a project key gets 401/403 here.
REFUSAL_REASONS = {
    401: "the key was rejected. The /v1/organization/* endpoints accept only an Admin API key "
         "(sk-admin-...) created by an organization owner at platform.openai.com/settings/organization/admin-keys.",
    403: "the key is not permitted to call this Administration API endpoint. Use an Admin API key "
         "(sk-admin-...); a project key (sk-proj-...) cannot read organization settings.",
    404: "OpenAI reported the resource as not found. The setting may not be configured for this organization.",
    429: "OpenAI rate-limited the call. Retry on the next evaluation.",
}


def detect_refusal(data):
    """Return (status, reason) when the payload is an error envelope, else None.

    The reason is fixed text. The vendor's own message is never copied in: OpenAI's
    invalid-key message echoes part of the key it was given.
    """
    if not isinstance(data, dict):
        return None
    err = data.get("error")
    if not (err or data.get("errorType") or data.get("status") == "Error"):
        return None
    status = data.get("statusCode") or data.get("status_code")
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    why = REFUSAL_REASONS.get(status, "the vendor call did not succeed.")
    if status:
        why = "HTTP " + str(status) + ": " + why
    return status, why


def read_list(obj):
    """(items, complete) for an OpenAI list envelope {object, data, has_more}.

    complete is True only when has_more is literally False: every page was read. A bare list,
    a missing has_more, or has_more true (the pager stopped early) is incomplete.
    """
    if not isinstance(obj, dict) or not isinstance(obj.get("data"), list):
        return None, False
    return [i for i in obj["data"] if isinstance(i, dict)], obj.get("has_more") is False


def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(float(value.strip()))
        except ValueError:
            return None
    return None


def now_ts():
    return datetime.now(timezone.utc).timestamp()


def not_measured(validation, reason, recommendation=None, extra=None, summary=None,
                 transformation_errors=None):
    """No verdict: the key is None and dataCollection.status is "error", so the evaluator
    shows Not evaluated instead of a failed check. extra carries facts really read (an
    event count of zero, the HTTP status) next to the missing verdict."""
    result = {KEY: None}
    if extra:
        result.update(extra)
    return create_response(result=result, validation=validation, fail_reasons=[reason],
                           recommendations=[recommendation] if recommendation else [],
                           input_summary=summary or {}, api_errors=[reason],
                           transformation_errors=transformation_errors)


def refused_or_unrecognised(data, validation, what):
    refusal = detect_refusal(data)
    if refusal:
        status, why = refusal
        return not_measured(validation, "The OpenAI call did not return data - " + why +
                            " This is a credential or reachability result, not a finding; the control's state is unknown.",
                            "Reconnect the OpenAI integration with an Admin API key.",
                            {"endpointReachable": False, "httpStatus": status})
    return not_measured(validation, what + " response not recognised - no OpenAI list or object in the payload.",
                        "Inspect the raw integration response.", {"endpointReachable": None})


def transform(input):
    try:
        if isinstance(input, dict) and "validation" in input:
            return evaluate({"data": input.get("data"), "validation": input.get("validation")})
        return evaluate(input)
    except Exception as exc:
        return not_measured(
            {"status": "error", "errors": [], "warnings": []},
            "The audit log response could not be read, so the "
            "control's state is unknown.",
            "Report this to the Spektrum integrations team with the raw API response.",
            transformation_errors=[str(exc)],
        )

def evaluate(input):
    data, validation = extract_input(input)
    items, complete = read_list(data)
    if items is None:
        return refused_or_unrecognised(data, validation, "Audit log")
    events = [e for e in items if isinstance(e.get("type"), str) and e.get("id")]
    if not items:
        reason = ("GET /v1/organization/audit_logs returned no events. OpenAI exposes no setting that says whether "
                  "audit logging is on, so an empty list cannot tell logging that is off from logging that is on "
                  "but has recorded nothing. The control was not measured.")
        return create_response(
            result={KEY: None, "events": 0},
            validation=validation,
            api_errors=[reason],
            recommendations=["Confirm in Organization settings > Data controls that audit logging is on and attach "
                             "that as evidence, or re-run once the organization has logged activity. Once enabled it "
                             "cannot be turned off from settings."],
            input_summary={"events": 0},
        )
    if not events:
        # Entries that are not audit events were not read as an answer: no verdict, never False.
        return not_measured(validation,
                            "GET /v1/organization/audit_logs returned entries but none is a recognisable audit event "
                            "(no id and type), so the control was not evaluated.",
                            "Inspect the raw integration response.",
                            {"events": 0})
    newest = events[0]
    ts = as_int(newest.get("effective_at"))
    age = None
    if ts is not None:
        age = round((now_ts() - ts) / 86400.0, 1)
    return create_response(
        result={KEY: True, "latestEventType": newest.get("type"), "latestEventAgeDays": age},
        validation=validation,
        pass_reasons=["The organization audit log is readable with the Admin API key and holds events "
                      "(latest: " + str(newest.get("type")) + ", " + str(age) + " days ago). OpenAI does not "
                      "let audit logging be switched off from settings once enabled."],
        input_summary={"events": len(events)},
    )
