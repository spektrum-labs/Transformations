"""Transformation: isOWAOfflineAccessDisabled (Microsoft 365 One-Click, method getOwaMailboxPolicies).

Value: True when Outlook on the web offline access is off for every OWA mailbox policy in use, i.e. AllowOfflineOn
is "NoComputers" on each of them. False when a policy in use allows offline access ("PrivateComputersOnly" or
"AllComputers"); the fail reason names it.

Input: the certificate-auth Exchange Online Lambda running scripts/GetOwaMailboxPolicies-Cert.ps1 (read-only
Get-OwaMailboxPolicy and Get-EXOCasMailbox, the Exchange.ManageAsApp app-only connection and Global Reader role
the other Exchange Online checks already use). The Lambda answers {"Success", "Output", "Error"}; Output carries
policies (Name, Identity, IsDefault, AllowOfflineOn), policyCount and usage. Usage counts OWA-enabled mailboxes
per policy; a mailbox with no policy assigned gets the default policy.

Which policies are "in use":
  * every policy is NoComputers -> True whatever the usage read says (no policy can allow offline access);
  * otherwise usage must be complete: a policy is in use when at least one OWA-enabled mailbox has it (or, for
    the default policy, has no policy assigned). True when no policy in use allows offline access, else False.

Not evaluated (value None, dataCollection "error"): an error body or PSError, success not true, no policy list,
an empty list, a policy list shorter than policyCount (partial), a policy without a Name or with an unrecognised
AllowOfflineOn value, and -- only when some policy allows offline access -- an incomplete or inconsistent usage
read, a usage entry naming no known policy, no default policy for unassigned mailboxes, or no OWA-enabled mailbox.
"""
import json
from datetime import datetime

KEY = "isOWAOfflineAccessDisabled"
META = {"transformationId": KEY, "vendor": "Microsoft", "category": "Productivity Suite"}
SAFE = "nocomputers"
KNOWN = ["nocomputers", "privatecomputersonly", "allcomputers"]
WRAPPERS = ["Output", "output", "apiResponse", "api_response", "response", "result", "rawResponse", "body", "data"]


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        return json.loads(text) if text else None
    return value


def truthy(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def to_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def short(value, limit=200):
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


def find_output(obj):
    """(output, error): the script's Output object (the dict carrying "policies"), under the Lambda envelope and
    Token-Service / IS wrappers, or the error that came back instead."""
    cur = obj
    for depth in range(8):
        try:
            cur = parse(cur)
        except Exception:
            return None, "The Exchange Online response is not JSON."
        if not isinstance(cur, dict):
            return None, None
        if cur.get("PSError"):
            return None, "Exchange Online returned an error: " + short(cur.get("PSError"))
        if "policies" in cur:
            return cur, None
        if cur.get("Success") is False or str(cur.get("Success")).strip().lower() == "false":
            return None, "The Exchange Online script did not complete: " + short(cur.get("Error") or "no detail")
        if cur.get("error") or cur.get("errors") or cur.get("errorType"):
            return None, "Exchange Online returned an error: " + short(cur.get("error") or cur.get("errorMessage") or cur.get("errors") or cur.get("errorType"))
        status = to_count(cur.get("statusCode") or cur.get("status_code"))
        if status is not None and status >= 400:
            return None, "Exchange Online returned HTTP " + str(status) + "."
        nxt = None
        for key in WRAPPERS:
            if cur.get(key) is not None:
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def respond(value, extra=None, problem=None, pass_reasons=None, fail_reasons=None, recommendations=None):
    result = {KEY: value}
    for k in (extra or {}):
        result[k] = extra[k]
    errors = [problem] if problem else []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if problem else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": extra or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": (fail_reasons or []) + errors,
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": META["transformationId"], "vendor": META["vendor"],
                         "category": META["category"]},
        },
    }


def unevaluated(problem, extra=None):
    return respond(None, extra=extra, problem=problem)


def read_policies(output):
    """(policies, None) with each policy as {"name", "identity", "isDefault", "allow"}, or (None, problem)."""
    if not truthy(output.get("success")):
        return None, "The Exchange Online script did not report success."
    raw = output.get("policies")
    if not isinstance(raw, list):
        return None, "No OWA mailbox policy list in the Exchange Online response."
    if not raw:
        return None, "Exchange Online returned no OWA mailbox policies; an empty list proves nothing."
    expected = to_count(output.get("policyCount"))
    if expected is None:
        return None, "The response carries no numeric policyCount, so a complete policy list cannot be shown."
    if len(raw) != expected:
        return None, ("Read " + str(len(raw)) + " of " + str(expected) + " OWA mailbox policies; "
                      "a partial policy list is not scored.")
    policies = []
    for p in raw:
        if not isinstance(p, dict):
            return None, "An OWA mailbox policy entry is not an object."
        name = str(p.get("Name") or "").strip()
        if not name:
            return None, "An OWA mailbox policy has no Name."
        allow = str(p.get("AllowOfflineOn") or "").strip()
        if allow.lower() not in KNOWN:
            return None, "OWA mailbox policy " + short(name, 80) + " has an unrecognised AllowOfflineOn value (" + short(allow, 40) + ")."
        policies.append({"name": name, "identity": str(p.get("Identity") or "").strip(),
                         "isDefault": truthy(p.get("IsDefault")), "allow": allow})
    return policies, None


def policies_in_use(output, policies):
    """(names in use, None) or (None, problem). Names are the policies' Name values."""
    usage = output.get("usage")
    try:
        usage = parse(usage)
    except Exception:
        usage = None
    if not isinstance(usage, dict) or not truthy(usage.get("complete")):
        detail = usage.get("error") if isinstance(usage, dict) else ""
        return None, "Which OWA mailbox policies are in use could not be read" + (": " + short(detail) if detail else ".")
    enabled = to_count(usage.get("owaEnabledMailboxCount"))
    unassigned = to_count(usage.get("unassignedMailboxCount"))
    by_policy = usage.get("byPolicy")
    try:
        by_policy = parse(by_policy)
    except Exception:
        by_policy = None
    if enabled is None or unassigned is None or not isinstance(by_policy, dict):
        return None, "The OWA mailbox usage read is missing its counts."
    if enabled == 0:
        return None, "No mailbox has Outlook on the web enabled; there is no policy in use to judge."
    lookup = {}
    for p in policies:
        lookup[p["name"].lower()] = p["name"]
        if p["identity"]:
            lookup[p["identity"].lower()] = p["name"]
    used = {}
    total = unassigned
    for assigned in by_policy:
        count = to_count(by_policy[assigned])
        if count is None:
            return None, "The OWA mailbox usage read has a non-numeric count."
        total = total + count
        if count == 0:
            continue
        name = lookup.get(str(assigned).strip().lower())
        if name is None:
            return None, "Mailboxes use OWA policy " + short(assigned, 80) + ", which is not in the policy list."
        used[name] = True
    if total != enabled:
        return None, ("The OWA mailbox usage read does not add up (" + str(total) + " assigned of " + str(enabled) +
                      " OWA-enabled mailboxes).")
    if unassigned > 0:
        defaults = [p["name"] for p in policies if p["isDefault"]]
        if len(defaults) != 1:
            return None, "Mailboxes without an OWA policy use the default policy, but the policy list has no single default."
        used[defaults[0]] = True
    return sorted(used), None


def transform(input):
    try:
        raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
        output, problem = find_output(raw)
        if problem:
            return unevaluated(problem)
        if output is None:
            return unevaluated("No OWA mailbox policy read (getOwaMailboxPolicies) in the response; nothing to evaluate.")
        policies, problem = read_policies(output)
        if problem:
            return unevaluated(problem)
        allowing = [p["name"] for p in policies if p["allow"].lower() != SAFE]
        extra = {"policyCount": len(policies), "policiesAllowingOffline": len(allowing)}
        if not allowing:
            return respond(True, extra, pass_reasons=[
                "All " + str(len(policies)) + " OWA mailbox policies set AllowOfflineOn to NoComputers."])
        used, problem = policies_in_use(output, policies)
        if problem:
            return unevaluated(problem + " Policies allowing offline access: " + short(", ".join(allowing[:5]), 300), extra)
        bad = [p["name"] + " (" + p["allow"] + ")" for p in policies if p["name"] in used and p["allow"].lower() != SAFE]
        extra["policiesInUse"] = len(used)
        extra["inUsePoliciesAllowingOffline"] = len(bad)
        if not bad:
            return respond(True, extra, pass_reasons=[
                "Every OWA mailbox policy in use (" + str(len(used)) + ") sets AllowOfflineOn to NoComputers; " +
                str(len(allowing)) + " unused policy(ies) allow offline access."])
        return respond(False, extra,
                       fail_reasons=["OWA mailbox policies in use allow offline access: " +
                                     short(", ".join(bad[:5]) + ("..." if len(bad) > 5 else ""), 400)],
                       recommendations=["Set AllowOfflineOn to NoComputers on every OWA mailbox policy in use "
                                        "(Set-OwaMailboxPolicy -AllowOfflineOn NoComputers)."])
    except Exception as e:
        return unevaluated("Transformation error: " + short(e))
