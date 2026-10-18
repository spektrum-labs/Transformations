"""
Transformation: isIPAllowlistEnabled
Vendor: SendGrid  |  Product: SendGrid  |  Category: Email Security

Integration-Service workflow getIpAccessPosture:
  GET /v3/access_settings/whitelist   (scope: access_settings.whitelist.read, under "Security")
  API reference: https://www.twilio.com/docs/sendgrid/api-reference/ip-access-management

True when the account's IP Access Management allow list holds at least one address: SendGrid
then accepts account access (the API and the sign-in) only from the listed addresses. False
when the list is empty, which means any address can reach the account: a successful read of an
empty list is the real state (False, "0 IP allow-list entries"), not a failed read. The contents
of the list (addresses) are never kept, only the count. Every entry must carry an ip; an entry
without one does not show an allowed address and the read is Not evaluated.
Fail closed: a 401/403 (for example a key without the scope), 5xx, timeout or other error, an
empty or unparsable body, or a body without the expected field is null with dataCollection status
"error" (Not evaluated), never a pass or a fail. A successful read that shows the control is not
configured is the real state and is False.
"""

import json
from datetime import datetime, timezone

VENDOR = "SendGrid"
PRODUCT = "SendGrid"
CATEGORY = "Email Security"
WRAPPERS = ("data", "response", "result", "apiResponse", "Output")
LIST_WRAPPERS = ("apiResponse", "data", "result", "results", "response")
MAX_NAMED = 10


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def find_leg(data, leg):
    """The leg the workflow merged under its output key, possibly under the usual
    Integration-Service wrappers. Returns (found, body)."""
    for depth in range(6):
        if not isinstance(data, dict):
            return False, None
        if leg in data:
            return True, data[leg]
        nxt = None
        for key in WRAPPERS:
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return False, None
        data = nxt
    return False, None


def as_int(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == int(value):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def flag(value):
    """True / False from a boolean or its string form; None for anything else."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("true", "yes", "on", "enabled"):
            return True
        if text in ("false", "no", "off", "disabled"):
            return False
    return None


def error_text(body):
    """Why a body is an error, or None: Integration-Service error envelopes, HTTP status
    envelopes (401 and 403 included) and SendGrid {"errors": [...]} bodies."""
    if isinstance(body, dict):
        if body.get("error") is True or body.get("errorType"):
            return ("Integration-Service error " + str(body.get("statusCode") or "") + ": " +
                    str(body.get("message") or body.get("errorMessage") or "")[:200]).strip()
        for key in ("statusCode", "status_code", "status"):
            code = as_int(body.get(key))
            if code is not None and code >= 400:
                return "HTTP " + str(code)
        errors = body.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            text = first.get("message") if isinstance(first, dict) else first
            return "SendGrid error: " + str(text)[:200]
        if isinstance(body.get("error"), str):
            return "SendGrid error: " + body.get("error")[:200]
    return None


def list_of(body):
    """(items, problem) for a leg that must be a list of objects, bare or under a wrapper."""
    if isinstance(body, list):
        return body, None
    if isinstance(body, dict):
        problem = error_text(body)
        if problem:
            return None, problem
        for key in LIST_WRAPPERS:
            if isinstance(body.get(key), list):
                return body[key], None
    return None, "unrecognised response"


def named(items):
    shown = items[:MAX_NAMED]
    more = len(items) - len(shown)
    return ", ".join(shown) + (" and " + str(more) + " more" if more > 0 else "")


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id="", findings=None):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "product": PRODUCT,
                         "category": CATEGORY},
        },
    }


def not_evaluated(key, transform_id, problem, summary=None):
    return build_response({key: None}, errors=[problem], summary=summary, transform_id=transform_id)

CRITERIA_KEY = "isIPAllowlistEnabled"
TRANSFORM_ID = "isipallowlistenabled"
LEG = "ipAllowlist"
MAX_ITEMS = 1000


def transform(input):
    try:
        found, body = find_leg(parse(input), LEG)
        if not found:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "no SendGrid IP access read in the response")
        problem = error_text(body)
        if problem:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/access_settings/whitelist: " + problem)
        if not isinstance(body, dict) or not isinstance(body.get("result"), list):
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/access_settings/whitelist: the response has no result list")
        items = body.get("result")
        if len(items) >= MAX_ITEMS:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/access_settings/whitelist returned " + str(len(items)) + " entries; the list may be cut off")
        for item in items:
            if not isinstance(item, dict):
                return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/access_settings/whitelist: an entry is not an object")
            if not str(item.get("ip") or "").strip():
                return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/access_settings/whitelist: an entry has no ip address")
        count = len(items)
        summary = {"allowlistEntries": count}
        result = {CRITERIA_KEY: count > 0, "allowlistEntries": count}
        if count > 0:
            return build_response(result, pass_reasons=["IP Access Management is on: " + str(count) + " allowed address" + ("" if count == 1 else "es")],
                                  summary=summary, transform_id=TRANSFORM_ID)
        return build_response(result, fail_reasons=["0 IP allow-list entries: the IP Access Management allow list is empty, so any address can reach the SendGrid account"],
                              recommendations=["In SendGrid, open Settings, IP Access Management and add the company's trusted addresses, keeping an address you can sign in from"],
                              summary=summary, transform_id=TRANSFORM_ID)
    except Exception as error:
        return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "transform error: " + str(error))
