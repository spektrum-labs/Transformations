"""
Transformation: sslDeepInspectionEnabled
Vendor: Palo Alto Networks Cloud NGFW (AWS)  |  Category: Firewalls

Integration-Service workflow getNgfwRulestackPosture (firewalls, then each running rulestack):
  firewalls   <- describeFirewall:  GET /v1/config/ngfirewalls/{name}
  rulestacks  <- describeRulestack: GET /v1/config/rulestacks/{name}

Value: True when the RUNNING configuration of every rulestack a firewall uses names an
Profiles.OutboundTrustCertificate (the certificate the firewall re-signs decrypted outbound
traffic with); False when any of them names none. A named certificate is the configuration that
turns outbound decryption on; it does not show that a security rule selects traffic for it.

Fail closed (Not evaluated, never a pass): a refused (401/403), expired-token, error-shaped,
empty, unrecognised or possibly cut-off read, a firewall with no rulestack, a rulestack with no
running configuration, or a Profiles object with no readable profile at all is null.

Source: public OpenAPI reference for Cloud NGFW for AWS (pan.dev, ManageRulestacks).
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


def bound_rulestack_names(top):
    """(names, problem): the rulestack each firewall uses, de-duplicated, in order."""
    listing = top.get("firewallList")
    if listing is not None:
        problem = list_problem(listing, "firewall list")
        if problem:
            return None, problem
    problem = top_problem(top, "firewalls")
    if problem:
        return None, problem
    firewalls = top.get("firewalls")
    if not isinstance(firewalls, list):
        return None, "firewalls: not returned"
    if not firewalls:
        return None, "firewalls: the account has no firewall, so there is nothing to measure"
    names = []
    for resp in firewalls:
        problem = response_problem(resp, "firewall read")
        if problem:
            return None, problem
        fw = resp["Response"].get("Firewall")
        if not isinstance(fw, dict):
            return None, "firewall read: no Firewall object in the answer"
        name = text_of(fw.get("RuleStackName")) or text_of(fw.get("GlobalRuleStackName"))
        if not name:
            return None, "firewall read: the firewall names no rulestack"
        if name not in names:
            names.append(name)
    return names, None


def running_profiles(top, names):
    """({rulestack name: its running Profiles}, problem)."""
    stacks = top.get("rulestacks")
    if not isinstance(stacks, list):
        return None, "rulestacks: not returned"
    by_name = {}
    for resp in stacks:
        problem = response_problem(resp, "rulestack read")
        if problem:
            return None, problem
        data = resp["Response"]
        name = text_of(data.get("RuleStackName"))
        running = data.get("RuleStackRunning")
        if name and isinstance(running, dict) and isinstance(running.get("Profiles"), dict):
            by_name[name] = running["Profiles"]
    out = {}
    for name in names:
        if name not in by_name:
            return None, ("rulestack " + name + " has no readable running configuration (never committed, "
                          "or its read was refused)")
        out[name] = by_name[name]
    return out, None


def load_profiles(input):
    """(profiles by bound rulestack, None) or (None, problem)."""
    data = parse(input)
    top = unwrap(data, ("firewalls",))
    if top is None:
        return None, error_text(data) or "no firewalls in the response"
    names, problem = bound_rulestack_names(top)
    if problem:
        return None, problem
    return running_profiles(top, names)


def combine(results):
    """results: list of (True | False | None, reason). Any False wins; else any None is unreadable."""
    off = [r for flag, r in results if flag is False]
    if off:
        return False, off
    unread = [r for flag, r in results if flag is None]
    if unread:
        return None, unread
    return True, []


KEY = "sslDeepInspectionEnabled"
KNOWN = ("AntiSpywareProfile", "AntiVirusProfile", "FileBlockingProfile", "VulnerabilityProfile",
         "URLFilteringProfile", "OutboundTrustCertificate", "OutboundUnTrustCertificate")


def judge(name, profiles):
    if not [field for field in KNOWN if field in profiles]:
        return None, "rulestack " + name + ": the running Profiles object has no readable profile"
    if text_of(profiles.get("OutboundTrustCertificate")):
        return True, ""
    return False, "rulestack " + name + ": no outbound trust certificate is set, so outbound decryption is off"


def transform(input):
    try:
        profiles, problem = load_profiles(input)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        results = [judge(name, profiles[name]) for name in profiles]
        value, reasons = combine(results)
        summary = {"rulestacks": len(profiles)}
        if value is None:
            return build_response({KEY: None}, errors=reasons[:5], summary=summary, transform_id=KEY)
        if value is False:
            return build_response({KEY: False}, fail_reasons=reasons, summary=summary,
                                  recommendations=["Set an outbound trust certificate on the rulestack and commit it so "
                                                   "encrypted outbound traffic is decrypted and inspected."],
                                  transform_id=KEY)
        return build_response({KEY: True}, pass_reasons=["Outbound decryption certificate set on "
                                                          + str(len(profiles)) + " rulestack(s)"],
                              summary=summary, transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
