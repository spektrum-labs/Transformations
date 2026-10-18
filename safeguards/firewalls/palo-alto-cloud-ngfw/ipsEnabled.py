"""
Transformation: ipsEnabled
Vendor: Palo Alto Networks Cloud NGFW (AWS)  |  Category: Firewalls

Integration-Service workflow getNgfwRulestackPosture, legs:
  firewallList  <- listFirewalls:     GET /v1/config/ngfirewalls
  firewalls     <- describeFirewall:  GET /v1/config/ngfirewalls/{name}, per firewall
  rulestackList <- listRulestacks:    GET /v1/config/rulestacks
  rulestacks    <- describeRulestack: GET /v1/config/rulestacks/{name}, per running rulestack

NOT WIRED: this key is not in the Integration-Service definition's retrievalTransformationArray, so
it shows as not covered. The file stays as a documented placeholder until a read can show both outcomes.

Value: None (Not evaluated) on every read. The reference allows only custom or BestPractice for
VulnerabilityProfile and defaults it to BestPractice, so a vendor reply can never show IPS is off
and "attached" would always be True. The key answers only after the read itself fails or after a
read that can be both True and False replaces this one. A refused (401/403), expired-token,
error-shaped, empty, unrecognised or possibly cut-off read, a rulestack with no running
configuration, or no firewall is null with the specific reason.

Source: public OpenAPI reference for Cloud NGFW for AWS (pan.dev, ManageRulestacks and
ManageNGFW). How a read asks for the running configuration is UNVERIFIED (see the method notes).
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
    """(names, problem): every rulestack (local and global) the firewalls use, de-duplicated, in order.
    The firewall list and the per-firewall reads must agree: a listed firewall nobody read is not
    a smaller estate."""
    listing = top.get("firewallList")
    listed = None
    if listing is not None:
        problem = list_problem(listing, "firewall list")
        if problem:
            return None, problem
        entries = listing["Response"].get("Firewalls")
        if isinstance(entries, list):
            listed = [text_of(entry.get("FirewallName")) if isinstance(entry, dict) else "" for entry in entries]
    problem = top_problem(top, "firewalls")
    if problem:
        return None, problem
    firewalls = top.get("firewalls")
    if not isinstance(firewalls, list):
        return None, "firewalls: not returned"
    if not firewalls:
        return None, "firewalls: the account has no firewall, so there is nothing to measure"
    names = []
    read = []
    for resp in firewalls:
        problem = response_problem(resp, "firewall read")
        if problem:
            return None, problem
        fw = resp["Response"].get("Firewall")
        if not isinstance(fw, dict):
            return None, "firewall read: no Firewall object in the answer"
        read.append(text_of(fw.get("FirewallName")))
        bound = [text_of(fw.get("RuleStackName")), text_of(fw.get("GlobalRuleStackName"))]
        bound = [name for name in bound if name]
        if not bound:
            return None, "firewall read: the firewall names no rulestack"
        for name in bound:
            if name not in names:
                names.append(name)
    if listed is not None:
        missing = [name for name in listed if not name or name not in read]
        if missing:
            return None, ("firewall list: " + str(len(missing)) + " listed firewall(s) have no read of their own, "
                          "so the rulestacks in use are not fully known")
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


KEY = "ipsEnabled"
REASON = ("the vendor reference allows only custom or BestPractice for VulnerabilityProfile and defaults it "
          "to BestPractice, so a read cannot show IPS is off or on; not evaluated until a read can")


def transform(input):
    try:
        profiles, problem = load_profiles(input)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        return build_response({KEY: None}, errors=[REASON], summary={"rulestacks": len(profiles)},
                              transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
