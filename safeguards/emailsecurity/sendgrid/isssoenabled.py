"""
Transformation: isSSOEnabled
Vendor: SendGrid  |  Product: SendGrid  |  Category: Email Security

Integration-Service workflow getSsoPosture:
  GET /v3/sso/integrations   (scope: sso.settings.read, "SSO Settings")
  API reference: https://www.twilio.com/docs/sendgrid/api-reference/single-sign-on-settings

True when at least one SAML single sign-on integration is configured, finished (the identity
provider setup is completed) and enabled, so people can sign in to SendGrid through the company
identity provider. False when the account has no integration, or none is both completed and
enabled. A successful read that lists no integration is the real state (False, "0 integrations"),
not a failed read. That every teammate actually signs in with SSO is a separate check
(isSSOEnforcedForAllUsers). SendGrid does not page this list: one call returns every
integration, so there is no cut-off guard (a True needs only one active integration).
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

CRITERIA_KEY = "isSSOEnabled"
TRANSFORM_ID = "isssoenabled"
LEG = "ssoIntegrations"

def transform(input):
    try:
        found, body = find_leg(parse(input), LEG)
        if not found:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "no SendGrid SSO read in the response")
        items, problem = list_of(body)
        if problem:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/sso/integrations: " + problem)
        active, inactive = [], []
        for item in items:
            if not isinstance(item, dict):
                return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/sso/integrations: an entry is not an object")
            enabled = flag(item.get("enabled"))
            completed = flag(item.get("completed_integration"))
            if enabled is None or completed is None:
                return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/sso/integrations: enabled or completed_integration was not returned")
            label = str(item.get("name") or "unnamed integration")[:60]
            if enabled and completed:
                active.append(label)
            else:
                inactive.append(label)
        summary = {"integrations": len(items), "active": len(active), "notActive": len(inactive)}
        result = {CRITERIA_KEY: len(active) > 0, "activeIntegrations": len(active)}
        findings = []
        if inactive:
            findings.append("SSO integrations that are not both completed and enabled: " + named(inactive))
        if active:
            return build_response(result, pass_reasons=["SAML single sign-on is configured and enabled: " + named(active)],
                                  summary=summary, transform_id=TRANSFORM_ID, findings=findings)
        reason = ("0 SAML single sign-on integrations are configured in SendGrid" if not items else
                  str(len(items)) + " SAML single sign-on integration" + ("" if len(items) == 1 else "s") +
                  " configured, 0 both completed and enabled")
        return build_response(result, fail_reasons=[reason],
                              recommendations=["In SendGrid, open Settings, Single Sign-On and configure and enable a SAML integration with the company identity provider"],
                              summary=summary, transform_id=TRANSFORM_ID, findings=findings)
    except Exception as error:
        return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "transform error: " + str(error))
