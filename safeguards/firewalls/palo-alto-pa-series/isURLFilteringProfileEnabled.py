"""
Transformation: isURLFilteringProfileEnabled
Vendor: Palo Alto Networks  |  Product: PA-Series Next-Generation Firewall (hardware)  |  Category: Firewalls

Value: Every enabled allow rule that can carry web traffic (application any, web-browsing or ssl) has a URL Filtering profile.

Wire: workflow getSecurityPolicyProfiles
  (X-PAN-KEY header; Integration-Service parses the XML reply with xmltodict:
  {"response": {"@status": "success", "result": {...}}})

Docs:
  PAN-OS XML API configuration (get/show) with xpath: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-request-types/get-active-configuration-api
  PAN-OS 11.1 configure CLI command hierarchy (element names): https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy

UNVERIFIED: Which rules face the internet is not in the configuration, so the web-capable test is by application (any, web-browsing, ssl); a profile's category actions are not read. vsys1 only.
Confirm against one real read-only connection before go-live.

Fail closed: an error status, an empty reply, a refused, error-shaped, unrecognised or possibly cut-off
body is null (Not evaluated), never False and never 0.
"""

import json
from datetime import datetime, timezone

VENDOR = "Palo Alto Networks"
PRODUCT = "PA-Series Next-Generation Firewall (hardware)"
CATEGORY = "firewalls"
# Integration-Service wraps a method or workflow body in these keys; "response" is also the root
# element of a PAN-OS XML API reply, which xmltodict keeps: {"response": {"@status": ..., "result": ...}}.
WRAPPERS = ("data", "response", "result", "apiResponse", "api_response", "Output", "_response_data")


def parse(value):
    """A body as a Python value: JSON text is decoded, anything undecodable (raw XML, empty) is None."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except Exception:
            return None
    if isinstance(value, str):
        if not value.strip():
            return None
        try:
            return json.loads(value)
        except Exception:
            return None
    return value


def find_pan(data, depth=0):
    """The PAN-OS <response> dict (the one carrying @status), looking through the usual wrappers."""
    data = parse(data)
    if depth > 6 or not isinstance(data, dict):
        return None
    if "@status" in data:
        return data
    for key in WRAPPERS:
        inner = data.get(key)
        if isinstance(inner, (dict, str, bytes)):
            found = find_pan(inner, depth + 1)
            if found is not None:
                return found
    return None


def sub(data, name, depth=0):
    """What a workflow stored under output key `name`, or None."""
    data = parse(data)
    if depth > 6 or not isinstance(data, dict):
        return None
    if name in data:
        return data[name]
    for key in WRAPPERS:
        inner = data.get(key)
        if isinstance(inner, (dict, str, bytes)):
            found = sub(inner, name, depth + 1)
            if found is not None:
                return found
    return None


def text_of(value):
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, dict):
        inner = value.get("#text")
        if isinstance(inner, str):
            return inner.strip()
    return None


def yes(value):
    t = text_of(value)
    return t is not None and t.lower() == "yes"


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def members(value):
    """<member> children as a list of strings (xmltodict gives a str for one, a list for many)."""
    if isinstance(value, dict):
        value = value.get("member")
    out = []
    for item in as_list(value):
        t = text_of(item)
        if t:
            out.append(t)
    return out


def entries(container):
    """<entry> children as a list of dicts (xmltodict gives a dict for one, a list for many)."""
    if isinstance(container, dict):
        if "entry" in container:
            container = container["entry"]
        else:
            container = [container]
    return [e for e in as_list(container) if isinstance(e, dict)]


def find_key(obj, key, depth=0):
    """The first value stored under `key` anywhere in nested dicts and lists."""
    if depth > 12:
        return None
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for inner in obj.values():
            found = find_key(inner, key, depth + 1)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for inner in obj:
            found = find_key(inner, key, depth + 1)
            if found is not None:
                return found
    return None


def message_of(pan):
    parts = []
    holders = [pan]
    if isinstance(pan.get("result"), dict):
        holders.append(pan["result"])
    for holder in holders:
        msg = holder.get("msg")
        if isinstance(msg, dict):
            msg = msg.get("line")
        texts = [text_of(m) for m in as_list(msg)]
        joined = "; ".join([t for t in texts if t])
        if joined:
            parts.append(joined)
    return "; ".join(parts)[:200]


def read(body, what):
    """(result, None) from a PAN-OS success body (result is None when the reply is empty),
    or (None, problem) for an error status, no PAN-OS body, or a read that may be cut off."""
    pan = find_pan(body)
    if pan is None:
        return None, what + ": no PAN-OS response in the body (refused, error, step error or unrecognised)"
    status = text_of(pan.get("@status"))
    if status != "success":
        return None, what + ": PAN-OS answered status '" + str(status) + "' " + message_of(pan)
    result = pan.get("result")
    if isinstance(result, dict):
        total = text_of(result.get("@total-count"))
        count = text_of(result.get("@count"))
        if total and count and total != count:
            return None, what + ": the reply may be cut off (count " + count + " of " + total + ")"
    return result, None


def need(body, what):
    """Like read, but an empty result is a problem too (object not present, or nothing readable)."""
    result, problem = read(body, what)
    if problem:
        return None, problem
    if result is None or result == "" or result == {}:
        return None, what + ": empty result (object not present, or nothing the key could read)"
    return result, None


def contains_key(obj, key, depth=0):
    if depth > 12:
        return False
    if isinstance(obj, dict):
        if key in obj:
            return True
        for inner in obj.values():
            if contains_key(inner, key, depth + 1):
                return True
    elif isinstance(obj, list):
        for inner in obj:
            if contains_key(inner, key, depth + 1):
                return True
    return False


def rule_list(result):
    rules = find_key(result, "rules")
    if rules is None:
        return [] if contains_key(result, "rules") else None
    return entries(rules)


def flat_members(value, depth=0):
    """Every <member> string under value (a zone, interface, address or user list), at any nesting up to 4 levels."""
    out = []
    if depth > 4:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "member":
                for item in as_list(v):
                    t = text_of(item)
                    if t:
                        out.append(t)
            else:
                out = out + flat_members(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            out = out + flat_members(v, depth + 1)
    return out


def covers_all(r, required, optional):
    """True only when the rule applies to all traffic: every required dimension (zones, addresses) is listed as
    any, every optional dimension that is listed (users, services, categories) is any, and nothing is negated.
    A missing required dimension is not proof, so it is not counted as all traffic."""
    for f in required:
        if "any" not in flat_members(r.get(f)):
            return False
    for f in optional:
        if f in r and "any" not in flat_members(r.get(f)):
            return False
    if yes(r.get("negate-source")) or yes(r.get("negate-destination")):
        return False
    return True


def name_list(items, limit=5):
    names = [text_of(i.get("@name")) or "?" for i in items]
    return ", ".join(names[:limit]) + (" and " + str(len(names) - limit) + " more" if len(names) > limit else "")


def respond(key, value, problem, info, title):
    info = info or {}
    api_errors = [problem] if problem else []
    now = datetime.now(timezone.utc).isoformat()
    return {
        "transformedResponse": {key: value},
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": info.get("summary", {})},
            "evaluation": {
                "passReasons": info.get("pass", []),
                "failReasons": info.get("fail", []),
                "recommendations": info.get("rec", []),
                "additionalFindings": [],
            },
            "metadata": {"evaluatedAt": now, "schemaVersion": "2.0", "transformationId": key,
                         "vendor": VENDOR, "product": PRODUCT, "category": CATEGORY, "title": title},
        },
    }


def run(key, title, evaluate, input):
    try:
        value, problem, info = evaluate(input)
    except Exception as e:
        value, problem, info = None, "the response could not be read (unexpected shape)", {}
    if problem:
        value = None
        info = dict(info or {})
        if not info.get("rec"):
            info["rec"] = ["Check that the management address is reachable from Spektrum and that the API "
                           "key's role may read this part of the configuration."]
    return respond(key, value, problem, info, title)



def profile_status(rule, kind, groups):
    """'yes' when the rule carries a profile of this kind (directly or through a profile group),
    'no' when it provably does not, 'unknown' when it names a group that could not be read."""
    setting = rule.get("profile-setting")
    if not isinstance(setting, dict):
        return "no"
    profiles = setting.get("profiles")
    if isinstance(profiles, dict) and members(profiles.get(kind)):
        return "yes"
    names = members(setting.get("group"))
    unknown = False
    for n in names:
        g = groups.get(n)
        if not isinstance(g, dict):
            unknown = True
            continue
        if members(g.get(kind)):
            return "yes"
    if unknown:
        return "unknown"
    return "no"


def group_map(*bodies):
    # pass the virtual system body first: a name found there wins over the same name in shared
    groups = {}
    for body in bodies:
        if body is None:
            continue
        result, problem = read(body, "profile groups")
        if problem or result is None:
            continue
        for g in entries(find_key(result, "profile-group")):
            n = text_of(g.get("@name"))
            if n and n not in groups:
                groups[n] = g
    return groups


def assess(data, kind, only_web, label):
    body = sub(data, "securityRules")
    result, problem = need(body, "security rules")
    if problem:
        return None, problem, {}
    rules = rule_list(result)
    if rules is None:
        return None, "security rules: no rules element in the reply", {}
    groups = group_map(sub(data, "profileGroups"), sub(data, "sharedProfileGroups"))
    live = [r for r in rules if not yes(r.get("disabled")) and text_of(r.get("action")) == "allow"]
    if only_web:
        web = []
        for r in live:
            apps = members(r.get("application"))
            if not apps or "any" in apps or "web-browsing" in apps or "ssl" in apps:
                web.append(r)
        live = web
    if not live:
        return None, "security rules: no enabled allow rule to judge for " + label, {}
    covered, missing, unknown = [], [], []
    for r in live:
        s = profile_status(r, kind, groups)
        if s == "yes":
            covered.append(r)
        elif s == "no":
            missing.append(r)
        else:
            unknown.append(r)
    summary = {"allowRulesJudged": len(live), "withProfile": len(covered), "withoutProfile": len(missing),
               "unresolvedGroup": len(unknown)}
    if missing:
        return False, None, {"summary": summary, "fail": [str(len(missing)) + " of " + str(len(live)) +
                             " enabled allow rules carry no " + label + ": " + name_list(missing)],
                             "rec": ["Attach a " + label + " (or a profile group that has one) to every allow rule."]}
    if unknown:
        return None, "security rules: " + str(len(unknown)) + " rule(s) name a profile group that could not be read", {"summary": summary}
    return True, None, {"summary": summary, "pass": ["All " + str(len(live)) + " enabled allow rules carry a " + label + "."]}


def evaluate(data):
    return assess(data, "url-filtering", True, "URL Filtering profile")

KEY = "isURLFilteringProfileEnabled"
TITLE = "URL Filtering Profile Enforced"


def transform(input):
    return run(KEY, TITLE, evaluate, input)
