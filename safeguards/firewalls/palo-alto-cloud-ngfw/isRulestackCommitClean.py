"""
Transformation: isRulestackCommitClean
Vendor: Palo Alto Networks Cloud NGFW (AWS)  |  Category: Firewalls

Integration-Service workflow getNgfwRulestackPosture, legs used:
  firewalls     <- describeFirewall: GET /v1/config/ngfirewalls/{name}, per firewall
  rulestackList <- listRulestacks:   GET /v1/config/rulestacks (asks for the uncommitted list)

Value: True when no rulestack that a firewall uses appears in the list's RuleStackUncommitted
array (each entry {RuleStackName, Operation: add | delete | update}); False when one does, since the
policy a firewall enforces then differs from the last committed configuration. An uncommitted
rulestack that no firewall uses is ignored.

Fail closed (Not evaluated, never a pass): a refused (401/403), expired-token, error-shaped,
empty, unrecognised or possibly cut-off read, a list that does not carry the RuleStackUncommitted
array at all (the read was not asked for it), or no firewall is null.

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


KEY = "isRulestackCommitClean"


def uncommitted_names(top):
    """(names with pending changes, problem)."""
    listing = top.get("rulestackList")
    problem = list_problem(listing, "rulestack list")
    if problem:
        return None, problem
    pending = listing["Response"].get("RuleStackUncommitted")
    if not isinstance(pending, list):
        return None, "rulestack list: no RuleStackUncommitted list, so pending changes were not read"
    names = []
    for entry in pending:
        if not isinstance(entry, dict) or not text_of(entry.get("RuleStackName")):
            return None, "rulestack list: an uncommitted entry is unreadable"
        names.append(text_of(entry["RuleStackName"]))
    return names, None


def transform(input):
    try:
        data = parse(input)
        top = unwrap(data, ("firewalls",))
        if top is None:
            return build_response({KEY: None}, errors=[error_text(data) or "no firewalls in the response"],
                                  transform_id=KEY)
        names, problem = bound_rulestack_names(top)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        pending, problem = uncommitted_names(top)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        dirty = [name for name in names if name in pending]
        summary = {"rulestacks": len(names), "uncommittedRulestacks": len(dirty)}
        if dirty:
            return build_response({KEY: False}, fail_reasons=[
                "rulestack " + name + " has changes that are not committed" for name in dirty],
                summary=summary,
                recommendations=["Validate and commit the pending rulestack changes, or revert them."],
                transform_id=KEY)
        return build_response({KEY: True}, pass_reasons=[
            "No pending changes on " + str(len(names)) + " rulestack(s) in use"], summary=summary,
            transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
