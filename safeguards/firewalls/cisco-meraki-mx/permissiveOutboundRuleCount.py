"""
Transformation: permissiveOutboundRuleCount
Vendor: Cisco Meraki MX  |  Category: Firewall
Claim (NSF-003, and the outbound clause of NSF-001): outbound traffic is limited to named services; no reachable
L3 rule allows every service to any destination.
Source: workflow firewallRulesByNetwork (already defined for defaultDenyInbound and isFirewallConfigured):
    {"networks": [<appliance network>, ...], "l3FirewallRules": [<GET /networks/{id}/appliance/firewall/l3FirewallRules>, ...]}
    each rules response: {"rules": [{"comment", "policy": allow|deny, "protocol", "srcCidr", "srcPort",
                                     "destCidr", "destPort", "syslogEnabled"}, ..., <implicit "Default rule">]}
Meraki MX L3 rules filter traffic leaving each VLAN, top-down, first match wins, and the GET appends Meraki's
implicit allow-any "Default rule" last.

A rule is PERMISSIVE when it allows (policy allow) traffic to any destination (destCidr Any) on every service:
protocol any, or protocol tcp / udp with destPort Any. A rule is REACHABLE when no earlier rule on the same network
already denies everything (deny, protocol any, srcCidr Any, destCidr Any). The implicit Default rule is counted
as one permissive rule on every network where it is reachable, because traffic that matches nothing above it is
allowed to everything.
Value: the number of reachable permissive rules across all appliance networks. Pass rule lessThan 0 (inclusive),
so only 0 passes. Allow-listed exceptions (a named server allowed to any port) are counted, because the
integration has no exception list; the reason names every rule counted so each can be reviewed.
Not evaluated (None with a dataCollection error): an empty, error or unrecognised body, no network list, a rules
response missing or in error for any network, a network list of 1,000 or more (the first page may not be the
last), networks and responses that do not pair up one to one, or a rules list that neither stops at a deny-all rule
nor ends with Meraki's Default rule (an incomplete list).
"""
import json
from datetime import datetime, timezone

KEY = "permissiveOutboundRuleCount"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output")

#: GET /organizations/{orgId}/networks returns at most 1,000 networks per page by default.
NETWORK_PAGE = 1000

MAX_NAMED = 20


def to_obj(raw):
    """A parsed JSON value, or None for an empty or unparseable body."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        text = raw.strip()
        if text == "":
            return None
        try:
            return json.loads(text)
        except Exception:
            return None
    return raw


def unwrap(raw):
    """(body, validation) with the Token-Service envelope and Integration-Service wrappers removed."""
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    cur = to_obj(raw)
    if isinstance(cur, dict) and "validation" in cur and "data" in cur:
        if isinstance(cur.get("validation"), dict):
            validation = cur.get("validation")
        cur = to_obj(cur.get("data"))
    for depth in range(8):
        if not isinstance(cur, dict) or "networks" in cur or "l3FirewallRules" in cur:
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None and isinstance(cur.get("data"), (dict, str)):
            nxt = to_obj(cur.get("data"))
        if nxt is None:
            break
        cur = nxt
    return cur, validation


def envelope_error(obj):
    """A short reason when obj is an error envelope rather than a Meraki body, else None."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        detail = obj.get("message") or err
        if isinstance(detail, dict):
            detail = detail.get("message") or json.dumps(detail)[:200]
        return "the call did not return data: " + str(detail)[:300]
    if isinstance(obj.get("errors"), list) and obj.get("errors") and "rules" not in obj:
        return "the call returned errors: " + str(obj.get("errors"))[:300]
    code = obj.get("statusCode")
    if code is None:
        code = obj.get("status_code")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "the call returned HTTP " + str(code)
    return None


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, api_errors=None):
    """Standardized transformation response (CONTRIBUTING.md)."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "Cisco Meraki MX",
                "category": "Firewall",
            },
        },
    }


def not_measured(validation, reason, recommendation=None, summary=None):
    """None with dataCollection status "error", so Token-Service records Not evaluated, not Failed."""
    return create_response(
        result={KEY: None},
        validation=validation,
        fail_reasons=[reason],
        recommendations=[recommendation] if recommendation else [],
        input_summary=summary or {},
        api_errors=[reason],
    )


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def unwrap_item(item):
    """A fanned-out response may still carry an apiResponse envelope or arrive as a JSON string."""
    item = to_obj(item)
    for depth in range(3):
        if not isinstance(item, dict):
            return item
        inner = None
        for w in WRAPPERS:
            if isinstance(item.get(w), (dict, list, str)):
                inner = to_obj(item.get(w))
                break
        if inner is None:
            break
        item = inner
    return item


def is_any(value):
    """True when a Meraki address or port field means any (Any, any, 0.0.0.0/0, or a list containing one)."""
    for part in str(value if value is not None else "").split(","):
        if part.strip().lower() in ("any", "0.0.0.0/0", "::/0"):
            return True
    return False


def is_permissive(rule):
    """An allow rule to any destination on every service."""
    if str(rule.get("policy") or "").strip().lower() != "allow":
        return False
    if not is_any(rule.get("destCidr")):
        return False
    protocol = str(rule.get("protocol") or "").strip().lower()
    if protocol == "any":
        return True
    if protocol in ("tcp", "udp", "tcp/udp") and is_any(rule.get("destPort")):
        return True
    return False


def is_deny_all(rule):
    """A deny rule from any source to any destination on every protocol: nothing below it is reached."""
    return (str(rule.get("policy") or "").strip().lower() == "deny"
            and str(rule.get("protocol") or "").strip().lower() == "any"
            and is_any(rule.get("srcCidr")) and is_any(rule.get("destCidr")))


def is_default_rule(rule):
    """Meraki's implicit last rule as the GET returns it: allow, protocol any, from Any to Any."""
    return (str(rule.get("policy") or "").strip().lower() == "allow"
            and str(rule.get("protocol") or "").strip().lower() == "any"
            and is_any(rule.get("srcCidr")) and is_any(rule.get("destCidr"))
            and (str(rule.get("comment") or "").strip().lower() == "default rule" or is_any(rule.get("destPort"))))


def rule_label(network, rule, position):
    comment = str(rule.get("comment") or "").strip()[:60]
    label = network + " rule " + str(position)
    if comment:
        label = label + " '" + comment + "'"
    return label + " (" + str(rule.get("protocol") or "?") + " from " + str(rule.get("srcCidr") or "?")[:40] + ")"


def network_rules(response):
    """(rules, None) for a readable L3 rules response, else (None, reason)."""
    if response is None:
        return None, "no rules response"
    if isinstance(response, list):
        rules = response
    elif isinstance(response, dict):
        why = envelope_error(response)
        if why:
            return None, why
        rules = response.get("rules")
    else:
        return None, "the rules response is not a JSON object"
    if not isinstance(rules, list):
        return None, "no rules list in the response"
    for r in rules:
        if not isinstance(r, dict):
            return None, "a rule entry is not an object"
    if len(rules) == 0:
        return None, "an empty rules list (Meraki always returns its Default rule, so this read is incomplete)"
    return rules, None


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled response as {"data": <response>, "validation": ...}, so networks and responses stay paired.
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
            body = unwrap(input.get("data"))[0]
        else:
            body, validation = unwrap(input)
        if body is None:
            return not_measured(validation, "The response body is empty; nothing was read from Meraki.")
        why = envelope_error(body)
        if why:
            return not_measured(validation, "Meraki: " + why + ". This is a credential or permission result, not a "
                                "finding.", "The L3 firewall rules read needs an API key with read access to the "
                                "organization's appliance networks.")
        if not isinstance(body, dict):
            return not_measured(validation, "Meraki: the response is not the firewallRulesByNetwork workflow result.")
        networks = to_obj(body.get("networks"))
        responses = to_obj(body.get("l3FirewallRules"))
        if not isinstance(networks, list) or not isinstance(responses, list):
            return not_measured(validation, "Meraki: the response carries no appliance network list and per-network "
                                "rules, so it cannot be shown which networks were read.")
        if len(networks) == 0:
            return not_measured(validation, "Meraki returned no appliance network, so no MX firewall rule was read.")
        if len(networks) >= NETWORK_PAGE:
            return not_measured(validation, "Meraki returned " + str(len(networks)) + " appliance networks, a full "
                                "page; the rest may not have been read.")
        if len(networks) != len(responses):
            return not_measured(validation, "Meraki returned " + str(len(networks)) + " appliance networks but " +
                                str(len(responses)) + " rules responses, so the rules cannot be paired with networks.")
        permissive = []
        unreadable = []
        per_network = {}
        for index in range(len(networks)):
            network = networks[index] if isinstance(networks[index], dict) else {}
            name = str(network.get("name") or network.get("id") or "network " + str(index))[:60]
            rules, why = network_rules(unwrap_item(responses[index]))
            if why:
                unreadable.append(name + ": " + why)
                continue
            count = 0
            position = 0
            stopped = False
            found = []
            for rule in rules:
                position = position + 1
                if is_permissive(rule):
                    count = count + 1
                    found.append(rule_label(name, rule, position))
                if is_deny_all(rule):
                    stopped = True
                    break
            if not stopped and not is_default_rule(rules[-1]):
                unreadable.append(name + ": the rules list neither stops at a deny-all rule nor ends with Meraki's "
                                  "Default rule, so it is incomplete")
                continue
            permissive = permissive + found
            per_network[name] = count
        summary = {"networksRead": len(per_network), "permissiveRules": len(permissive),
                   "permissiveRuleNames": permissive[:MAX_NAMED], "networksNotRead": unreadable[:MAX_NAMED]}
        if unreadable:
            return not_measured(validation, "Meraki: the L3 firewall rules of " + str(len(unreadable)) + " of " +
                                str(len(networks)) + " appliance network(s) could not be read (" +
                                name_list(unreadable) + "), so the count would be incomplete.", None, summary)
        if permissive:
            return create_response(
                result={KEY: len(permissive)},
                validation=validation,
                fail_reasons=[str(len(permissive)) + " reachable L3 rule(s) across " + str(len(networks)) +
                              " appliance network(s) allow every service to any destination: " + name_list(permissive) +
                              ". A 'Default rule' entry means traffic that matches no rule above it leaves on any port."],
                recommendations=["Allow outbound only the services that are needed (for example TCP 80 and 443, DNS to "
                                 "named resolvers) and add a final deny rule (protocol Any, source Any, destination "
                                 "Any) above Meraki's implicit Default rule on each network named."],
                input_summary=summary,
            )
        return create_response(
            result={KEY: 0},
            validation=validation,
            pass_reasons=["No reachable L3 rule on any of " + str(len(networks)) + " appliance network(s) allows every "
                          "service to any destination; each ends with an explicit deny above the Default rule."],
            input_summary=summary,
        )
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
