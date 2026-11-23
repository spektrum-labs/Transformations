"""
Transformation: isSSOEnforcedForAllUsers
Vendor: SendGrid  |  Product: SendGrid  |  Category: Email Security

Integration-Service workflow getSsoEnforcementPosture:
  GET /v3/teammates?limit=500&offset=...   (scope: teammates.read; paged until a short page)
  API reference: https://www.twilio.com/docs/sendgrid/api-reference/teammates

True when every teammate in the account has is_sso true, so every listed login signs in
through the company identity provider. False when any teammate has is_sso false; the evidence is
the count and the usernames (the part before any "@", never an email address). SendGrid's parent
account owner login is outside the teammates list and is not judged here. Whether an SSO
integration exists at all is a separate check (isSSOEnabled).

Fail closed: a 401/403 (for example a key without the teammates.read scope), 5xx, timeout or
other error, an empty or unparsable body, a body without the expected field, an empty teammates
list, a read cut off by the page cap, or a read the workflow does not report as complete
(paginationStats.teammates.paginationTruncated must be false) is null with dataCollection status "error"
(Not evaluated), never a pass or a fail.
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

CRITERIA_KEY = "isSSOEnforcedForAllUsers"
TRANSFORM_ID = "isssoenforcedforallusers"
LEG = "teammates"
OWNER_NOTE = "SendGrid's parent account owner login is outside the teammates list and was not judged"


def short_name(item):
    """The username without any @domain, so an email-style username is never shown whole."""
    name = str(item.get("username") or "").strip()
    if "@" in name:
        name = name.split("@", 1)[0]
    return name[:40] or "unnamed teammate"


def find_marked(data, leg):
    """The container that carries the leg (and so its pagination markers), under the usual wrappers."""
    for depth in range(6):
        if not isinstance(data, dict):
            return None
        if leg in data:
            return data
        nxt = None
        for key in WRAPPERS:
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return None
        data = nxt
    return None


def completeness(data, leg, path):
    """None when the workflow reports the paged read of `leg` was complete (paginationStats[leg].paginationTruncated
    is exactly false). Otherwise the reason it cannot be trusted as the whole list: marked cut off by the page cap,
    or no completeness marker at all (the Integration-Service step must set reportPagination)."""
    marked = find_marked(data, leg)
    for container in (marked, data):
        if isinstance(container, dict) and container.get("paginationTruncated") is True:
            return path + ": the read was cut off by the page cap; not every entry was read"
    stats = marked.get("paginationStats") if isinstance(marked, dict) else None
    state = stats.get(leg) if isinstance(stats, dict) else None
    if isinstance(state, dict) and state.get("paginationTruncated") is True:
        return path + ": the read was cut off by the page cap; not every entry was read"
    if not isinstance(state, dict) or state.get("paginationTruncated") is not False:
        return path + ": the workflow did not report whether the paged read was complete"
    return None


def transform(input):
    try:
        data = parse(input)
        found, body = find_leg(data, LEG)
        if not found:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "no SendGrid teammates read in the response")
        items, problem = list_of(body)
        if problem:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/teammates: " + problem)
        incomplete = completeness(data, LEG, "GET /v3/teammates")
        if incomplete:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, incomplete)
        if not items:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/teammates returned no teammates")
        enforced, not_sso = 0, []
        for item in items:
            if not isinstance(item, dict):
                return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/teammates: an entry is not an object")
            state = flag(item.get("is_sso"))
            if state is None:
                return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/teammates: is_sso was not returned as true or false for an entry")
            if state:
                enforced += 1
            else:
                not_sso.append(short_name(item))
        total = len(items)
        summary = {"teammates": total, "ssoTeammates": enforced, "nonSsoTeammates": len(not_sso)}
        result = {CRITERIA_KEY: len(not_sso) == 0, "teammatesTotal": total, "teammatesWithSso": enforced,
                  "teammatesWithoutSso": len(not_sso)}
        findings = [OWNER_NOTE]
        if not_sso:
            return build_response(result, fail_reasons=[
                str(len(not_sso)) + " of " + str(total) + " teammates do not sign in with SSO (is_sso false): " + named(not_sso)],
                recommendations=["In SendGrid, open Settings, Teammates and move each remaining teammate to single sign-on (or remove the login)"],
                summary=summary, transform_id=TRANSFORM_ID, findings=findings)
        return build_response(result, pass_reasons=["All " + str(total) + " teammates sign in with SSO (is_sso true)"],
                              summary=summary, transform_id=TRANSFORM_ID, findings=findings)
    except Exception as error:
        return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "transform error: " + str(error))
