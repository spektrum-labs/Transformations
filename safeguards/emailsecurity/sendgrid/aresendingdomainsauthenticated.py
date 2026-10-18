"""
Transformation: areSendingDomainsAuthenticated
Vendor: SendGrid  |  Product: SendGrid  |  Category: Email Security

Integration-Service workflow getSenderAuthenticationPosture:
  GET /v3/whitelabel/domains?limit=100&offset=...   (paged until a short page; scope: whitelabel.read, "Sender Authentication")
  API reference: https://www.twilio.com/docs/sendgrid/api-reference/domain-authentication

True when the account has at least one authenticated sending domain and every authenticated
domain has a record SendGrid reports as valid (valid is true: the DNS records for the SPF and
DKIM alignment resolve), so mail from those domains passes DKIM and SPF alignment checks. False
when the account has no authenticated domain (a successful read of an empty list is the real
state, "0 authenticated sending domains", not a failed read), or a domain has no valid record. A stale invalid
duplicate beside a valid record for the same domain is reported as a finding and does not fail
the check. Authentication of a domain that sends through another provider is out of scope.

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

CRITERIA_KEY = "areSendingDomainsAuthenticated"
TRANSFORM_ID = "aresendingdomainsauthenticated"

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


def group_by_domain(items, label, dns_keys):
    """(valid, invalid, partial, problem). valid: domains with at least one fully valid record;
    invalid: domains where no record is valid; partial: names of stale invalid duplicates left
    beside a valid record for the same domain."""
    states = {}
    for item in items:
        if not isinstance(item, dict):
            return None, None, None, label + ": an entry is not an object"
        domain = str(item.get("domain") or "").strip().lower()
        valid = flag(item.get("valid"))
        if not domain or valid is None:
            return None, None, None, label + ": domain or valid was not returned for an entry"
        states.setdefault(domain, []).append(valid)
    valid_domains = sorted([d for d in states if True in states[d]])
    invalid_domains = sorted([d for d in states if True not in states[d]])
    stale = sorted([d for d in states if True in states[d] and False in states[d]])
    return valid_domains, invalid_domains, stale, None

LEG = "authenticatedDomains"


def transform(input):
    try:
        data = parse(input)
        found, body = find_leg(data, LEG)
        if not found:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "no SendGrid domain authentication read in the response")
        items, problem = list_of(body)
        if problem:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /v3/whitelabel/domains: " + problem)
        incomplete = completeness(data, LEG, "GET /v3/whitelabel/domains")
        if incomplete:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, incomplete)
        valid, invalid, stale, problem = group_by_domain(items, "GET /v3/whitelabel/domains", ())
        if problem:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, problem)
        summary = {"records": len(items), "domainsValid": valid, "domainsInvalid": invalid, "domainsWithStaleRecord": stale}
        result = {CRITERIA_KEY: len(valid) > 0 and not invalid, "authenticatedDomains": len(valid), "domainsWithoutValidRecord": len(invalid)}
        findings = []
        if stale:
            findings.append("Domains that also hold an invalid, stale authentication record (delete it in SendGrid): " + named(stale))
        if not items:
            return build_response(result, fail_reasons=["0 authenticated sending domains in SendGrid"],
                                  recommendations=["In SendGrid, open Settings, Sender Authentication and authenticate the domain mail is sent from"],
                                  summary=summary, transform_id=TRANSFORM_ID, findings=findings)
        if invalid:
            return build_response(result, fail_reasons=["No valid SendGrid domain authentication record for: " + named(invalid)],
                                  recommendations=["Publish the DNS records SendGrid lists for each domain and verify them in Settings, Sender Authentication"],
                                  summary=summary, transform_id=TRANSFORM_ID, findings=findings)
        return build_response(result, pass_reasons=["Every authenticated sending domain has a valid record: " + named(valid)],
                              summary=summary, transform_id=TRANSFORM_ID, findings=findings)
    except Exception as error:
        return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "transform error: " + str(error))
