"""
Transformation: firewallLoggingEnabled
Vendor: Palo Alto Networks Cloud NGFW (AWS)  |  Category: Firewalls

Integration-Service workflow getNgfwLogProfiles, legs:
  firewallList <- listFirewalls:          GET /v1/config/ngfirewalls
  logProfiles  <- getFirewallLogProfile:  GET /v1/config/ngfirewalls/{name}/logprofile, per firewall

Value: True when every firewall in the firewall list has its log profile read and every one of
those profiles has a non-blank LogDestination for each of the TRAFFIC, THREAT and DECRYPTION log
types (the vendor's enum spells the last one DESCRYPTION; both spellings count); False when a
firewall's log profile lists destinations and lacks one of them. The bundle names all three. The
firewall list is required: a listed firewall with no log profile read of its own (matched by
FirewallName) is never counted as logging.

Fail closed (Not evaluated, never a pass): a refused (401/403), expired-token, error-shaped, empty,
unrecognised or possibly cut-off read, a missing, refused, unreadable or paged firewall list, a
listed firewall with no log profile read, a log profile answer with no LogDestinationConfigs or an
empty list (the reference does not say the field is absent when no log profile is set, so absence
is not "not logging"), a failed per-firewall read, or no firewall is null. One firewall that is
not logging makes the answer False even if another could not be read or is missing.

Source: public OpenAPI reference for Cloud NGFW for AWS (pan.dev, ManageLogProfiles).
"""

import json
from datetime import datetime, timezone

VENDOR = "Palo Alto Networks Cloud NGFW"
CATEGORY = "Firewalls"
WRAPPERS = ("data", "response", "result", "apiResponse", "Output")


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def unwrap(data, keys):
    """The first dict (under the usual Integration-Service wrappers) that carries one of keys."""
    for depth in range(6):
        if not isinstance(data, dict):
            return None
        for key in keys:
            if key in data:
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


def error_text(body):
    """Why a body is an error, or None."""
    if not isinstance(body, dict):
        return None
    if body.get("error") is True or body.get("errorType"):
        return "Integration-Service error " + str(body.get("statusCode") or "") + ": " + str(
            body.get("message") or body.get("errorMessage") or "")[:200]
    code = body.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code)
    if body.get("message") and "Response" not in body:
        return "vendor error: " + str(body.get("message"))[:200]
    return None


def response_problem(resp, label):
    """Why one vendor answer cannot be read, or None. Every answer is
    {"Response": {...}, "ResponseStatus": {"ErrorCode": 0}}; any other ErrorCode is a failure."""
    if not isinstance(resp, dict):
        return label + ": the response is not an object"
    text = error_text(resp)
    if text:
        return label + ": " + text
    status = resp.get("ResponseStatus")
    if isinstance(status, dict):
        code = status.get("ErrorCode")
        if code is not None and str(code).strip() not in ("0", ""):
            return label + ": vendor error " + str(code) + " " + str(status.get("Reason") or "")[:120]
    if not isinstance(resp.get("Response"), dict):
        return label + ": no Response object in the answer"
    return None


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id=""):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def text_of(value):
    return value.strip() if isinstance(value, str) else ""


def top_problem(top, label):
    """A cut-off or partly failed fan-out is never a smaller estate."""
    if top.get("iterateTruncated"):
        return label + ": more items exist than were read"
    count = top.get("itemErrors")
    if isinstance(count, int) and not isinstance(count, bool) and count > 0:
        return label + ": " + str(count) + " item read(s) failed"
    return None


def list_problem(listing, label):
    """One page of a vendor list: refused, unreadable, or with a NextToken (more behind it)."""
    problem = response_problem(listing, label)
    if problem:
        return problem
    if listing["Response"].get("NextToken"):
        return label + ": the list has more pages than were read"
    return None


KEY = "firewallLoggingEnabled"
REQUIRED = (("TRAFFIC",), ("THREAT",), ("DECRYPTION", "DESCRYPTION"))


def judge(resp):
    """(True | False | None, reason) for one firewall's log profile answer."""
    problem = response_problem(resp, "log profile read")
    if problem:
        return None, problem
    data = resp["Response"]
    name = text_of(data.get("FirewallName"))
    label = name or "a firewall"
    configs = data.get("LogDestinationConfigs")
    if configs is None or (isinstance(configs, list) and not configs):
        return None, ("firewall " + label + ": the log profile returned no LogDestinationConfigs, and the "
                      "reference does not say that means no logging")
    if not isinstance(configs, list):
        return None, "log profile read: LogDestinationConfigs is unreadable"
    covered = []
    for entry in configs:
        if not isinstance(entry, dict):
            return None, "log profile read: a destination entry is unreadable"
        if text_of(entry.get("LogDestination")):
            covered.append(text_of(entry.get("LogType")).upper())
    missing = [kinds[0] for kinds in REQUIRED if not [kind for kind in kinds if kind in covered]]
    if missing:
        return False, "firewall " + label + ": no log destination for " + ", ".join(missing) + " logs"
    return True, ""


def listed_firewalls(top):
    """(names, problem): the firewall names the firewall list holds. The list is required: without it
    nothing says which firewalls exist, so a firewall nobody read could be missing."""
    listing = top.get("firewallList")
    if listing is None:
        return None, "firewall list: not read, so it is not known which firewalls exist"
    problem = list_problem(listing, "firewall list")
    if problem:
        return None, problem
    entries = listing["Response"].get("Firewalls")
    if not isinstance(entries, list):
        return None, "firewall list: no Firewalls array in the answer"
    names = []
    for entry in entries:
        name = text_of(entry.get("FirewallName")) if isinstance(entry, dict) else ""
        if not name:
            return None, "firewall list: a listed firewall has no readable name"
        if name not in names:
            names.append(name)
    return names, None


def read_firewall_names(profiles):
    """The FirewallName of every log profile answer that carries one."""
    out = set()
    for resp in profiles:
        if isinstance(resp, dict) and isinstance(resp.get("Response"), dict):
            name = text_of(resp["Response"].get("FirewallName"))
            if name:
                out.add(name)
    return out


def transform(input):
    try:
        data = parse(input)
        top = unwrap(data, ("logProfiles",))
        if top is None:
            return build_response({KEY: None}, errors=[error_text(data) or "no logProfiles in the response"],
                                  transform_id=KEY)
        listed, problem = listed_firewalls(top)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        problem = top_problem(top, "log profiles")
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        profiles = top.get("logProfiles")
        if not isinstance(profiles, list) or not profiles or not listed:
            return build_response({KEY: None}, errors=["log profiles: no firewall was read, so nothing was measured"],
                                  transform_id=KEY)
        results = [judge(resp) for resp in profiles]
        off = [reason for flag, reason in results if flag is False]
        unread = [reason for flag, reason in results if flag is None]
        have = read_firewall_names(profiles)
        missing = [name for name in listed if name not in have]
        if missing:
            unread.append("firewall list: " + str(len(missing)) + " listed firewall(s) have no log profile read, "
                          "so they are not shown to be logging")
        summary = {"firewalls": len(profiles), "listedFirewalls": len(listed), "notLogging": len(off),
                   "unreadable": len(unread)}
        if off:
            return build_response({KEY: False}, fail_reasons=off, summary=summary,
                                  recommendations=["Configure a log destination for traffic, threat and decryption "
                                                   "logs on each firewall's log profile."], transform_id=KEY)
        if unread:
            return build_response({KEY: None}, errors=unread[:5], summary=summary, transform_id=KEY)
        return build_response({KEY: True}, pass_reasons=[
            "Traffic, threat and decryption logs have a destination on " + str(len(profiles)) + " firewall(s)"],
            summary=summary, transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
