"""
Transformation: isOutboundMinimumTLSVersionSecure
Vendor: SendGrid  |  Product: SendGrid  |  Category: Email Security

Integration-Service workflow getEnforcedTlsPosture:
  GET /v3/user/settings/enforced_tls   (scope: user.settings.enforced_tls.read, "Enforced TLS")
  API reference: https://www.twilio.com/docs/sendgrid/api-reference/settings-enforced-tls

True when TLS is required (require_tls is true) and the minimum TLS version SendGrid accepts is
1.2 or higher. False when the minimum version is below 1.2 (TLS 1.0 and 1.1 are deprecated), or
when TLS is not required, because SendGrid applies the minimum version only to mail it delivers
under a required-TLS policy. 
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

LEG = "enforcedTls"


def read_tls(input):
    """(body, problem): the enforced TLS settings object."""
    found, body = find_leg(parse(input), LEG)
    if not found:
        return None, "no SendGrid enforced TLS read in the response"
    problem = error_text(body)
    if problem:
        return None, "GET /v3/user/settings/enforced_tls: " + problem
    if not isinstance(body, dict) or not body:
        return None, "GET /v3/user/settings/enforced_tls: empty or unrecognised response"
    return body, None

CRITERIA_KEY = "isOutboundMinimumTLSVersionSecure"
TRANSFORM_ID = "isoutboundminimumtlsversionsecure"
SECURE_MINIMUM = 1.2


def version_of(value):
    """The TLS version as a number, from a number or a numeric string; None otherwise."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        parts = text.split(".")
        if text and len(parts) <= 2 and all(p.isdigit() for p in parts):
            return float(text)
    return None


def transform(input):
    try:
        body, problem = read_tls(input)
        if problem:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, problem)
        required = flag(body.get("require_tls"))
        version = version_of(body.get("version"))
        if required is None:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "require_tls was not returned as true or false")
        if version is None or version <= 0:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "the minimum TLS version (version) was not returned")
        summary = {"requireTls": required, "minimumTlsVersion": version}
        result = {CRITERIA_KEY: False, "minimumTlsVersion": version}
        recommendation = ["In SendGrid, open Settings, Mail Settings, Enforced TLS, turn on Require TLS and set the minimum TLS version to 1.2 or higher"]
        if version < SECURE_MINIMUM:
            return build_response(result, fail_reasons=["The minimum TLS version is " + str(version) + ", below 1.2"],
                                  recommendations=recommendation, summary=summary, transform_id=TRANSFORM_ID)
        if not required:
            return build_response(result, fail_reasons=["The minimum TLS version is " + str(version) + " but TLS is not required, so SendGrid does not apply it"],
                                  recommendations=recommendation, summary=summary, transform_id=TRANSFORM_ID)
        result[CRITERIA_KEY] = True
        return build_response(result, pass_reasons=["TLS is required and the minimum version is " + str(version)],
                              summary=summary, transform_id=TRANSFORM_ID)
    except Exception as error:
        return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "transform error: " + str(error))
