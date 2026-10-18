"""
Transformation: permissiveOutboundRuleCount
Vendor: Fortinet FortiGate (FortiOS REST API)  |  Category: Firewall
Claim (NSF-003, and the outbound clause of NSF-001): outbound traffic is limited to named services; no enabled
firewall policy accepts every service from an internal interface to any internet destination.
Source: a new workflow getOutboundPolicyEvidence merging four read-only FortiOS cmdb calls under output keys:
    firewallPolicies  GET /api/v2/cmdb/firewall/policy   (the existing getFirewallPolicies method)
    systemInterfaces  GET /api/v2/cmdb/system/interface  (name, role lan | wan | dmz | undefined)
    systemZones       GET /api/v2/cmdb/system/zone       (zone name and member interfaces)
    sdwan             GET /api/v2/cmdb/system/sdwan      (SD-WAN zones; optional: absent on FortiOS 6.2 and older)
Each FortiOS body: {"http_method": "GET", "results": [...], "vdom", "status": "success", "http_status": 200}.

A policy is PERMISSIVE OUTBOUND when it is enabled (status enable, the default), its action is accept, it does not
use internet-service destinations, its service list contains ALL, its destination list contains the built-in any
address "all", and at least one destination interface is internet-facing: an interface with role wan, a zone with a
wan member, an SD-WAN zone (virtual-wan-link or any zone in system/sdwan), or "any".
Value: the number of permissive outbound policies. Pass rule lessThan 0 (inclusive), so only 0 passes. Allow-listed
exceptions are counted (the integration has no exception list); the reason names each policy so it can be reviewed.
Scope and limits, stated in every reason: the API token's VDOM only; the consolidated policy table (IPv4 dstaddr and
IPv6 dstaddr6 since FortiOS 6.4); IPv6 policies in the separate policy6 table of FortiOS 6.2 and older are not read;
named address objects or service groups that happen to cover everything are not expanded (only the built-in "all"
address and "ALL" service are read). A policy whose service or destination is negated (service-negate,
dstaddr-negate, dstaddr6-negate) does not match that field.
Not evaluated (None with a dataCollection error): an empty, error or unrecognised body; the policy, interface or
zone read missing, not successful or partial (matched_count above the results returned; next_idx is not read as a
cursor, because FortiOS 7.x sends it on complete reads too); or, when no permissive policy is confirmed, an accept-ALL-to-all policy whose
destination interface cannot be resolved to an interface or zone. A confirmed permissive policy is a failure even
when others are unresolved (they can only add to the count; the reason names them).
"""
import json
from datetime import datetime, timezone

KEY = "permissiveOutboundRuleCount"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "rawResponse")

PARTS = ("firewallPolicies", "systemInterfaces", "systemZones", "sdwan")

MAX_NAMED = 20

LIMITS = ("Scope: this VDOM's consolidated policy table (IPv4 dstaddr and IPv6 dstaddr6); IPv6 policies kept in the "
          "separate policy6 table of FortiOS 6.2 and older are not read, and named address objects or service groups "
          "that cover everything are not expanded.")


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
        if not isinstance(cur, dict):
            break
        found = False
        for p in PARTS:
            if p in cur:
                found = True
        if found:
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
    """A short reason when obj is an error envelope rather than a FortiOS body, else None."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        detail = obj.get("message") or err
        if isinstance(detail, dict):
            detail = detail.get("message") or json.dumps(detail)[:200]
        return "the call did not return data: " + str(detail)[:300]
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
                "vendor": "Fortinet FortiGate",
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


def fortios_body(part):
    """(body, None) for a successful FortiOS cmdb read inside a workflow part, else (None, reason).

    The part may be the FortiOS body itself, or the Integration-Service method result that carries it under
    apiResponse / rawResponse beside returnSpec fields (getFirewallPolicies also returns "policies", which
    defaults to [] on failure and is therefore never read here).
    """
    cur = to_obj(part)
    for depth in range(5):
        if cur is None:
            return None, "missing"
        if not isinstance(cur, dict):
            return None, "not a JSON object"
        why = envelope_error(cur)
        if why:
            return None, why
        if "results" in cur and ("http_status" in cur or "status" in cur or "http_method" in cur):
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None:
            return None, "no FortiOS results in the response"
        cur = nxt
    if not (isinstance(cur, dict) and "results" in cur):
        return None, "no FortiOS results in the response"
    status = str(cur.get("status") or "").strip().lower()
    http_status = cur.get("http_status")
    if isinstance(http_status, str) and http_status.strip().isdigit():
        http_status = int(http_status.strip())
    if status not in ("", "success") or (http_status is not None and http_status != 200):
        return None, "FortiOS answered status " + str(cur.get("status")) + " (HTTP " + str(http_status) + ")"
    if status == "" and http_status is None:
        return None, "the FortiOS body carries neither status nor http_status, so success cannot be shown"
    # FortiOS 7.x list bodies carry matched_count and next_idx even for a complete read (next_idx is then the
    # index of the last entry returned), so next_idx is not read as a cursor. A read is partial when more entries
    # matched than were returned.
    matched = as_int(cur.get("matched_count"))
    results = cur.get("results")
    if matched is not None and isinstance(results, list) and matched > len(results):
        return None, ("a partial read: FortiOS matched " + str(matched) + " entries and returned " + str(len(results)))
    return cur, None


def as_int(value):
    """A whole number from an int or a digit string, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def results_list(body):
    results = body.get("results")
    if isinstance(results, dict):
        results = [results]
    if not isinstance(results, list):
        return None
    for r in results:
        if not isinstance(r, dict):
            return None
    return results


def names(entries):
    """The names in a FortiOS member list ([{"name": "wan1"}], [{"interface-name": "port1"}], or strings)."""
    out = []
    if isinstance(entries, str):
        entries = [x for x in entries.replace(",", " ").split(" ") if x]
    if not isinstance(entries, list):
        return out
    for e in entries:
        if isinstance(e, dict):
            n = e.get("name") or e.get("interface-name") or e.get("q_origin_key")
        else:
            n = e
        if n is not None and str(n).strip():
            out.append(str(n).strip())
    return out


def lower_set(items):
    return set(str(x).strip().lower() for x in items)


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled workflow result as {"data": <response>, "validation": ...}, so every part keeps its status.
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
            body = unwrap(input.get("data"))[0]
        else:
            body, validation = unwrap(input)
        if body is None:
            return not_measured(validation, "The response body is empty; nothing was read from the FortiGate.")
        why = envelope_error(body)
        if why:
            return not_measured(validation, "FortiGate: " + why + ". This is a credential or permission result, not "
                                "a finding.")
        if not isinstance(body, dict) or "firewallPolicies" not in body:
            return not_measured(validation, "FortiGate: the response is not the getOutboundPolicyEvidence workflow "
                                "result (no firewallPolicies part).")
        parsed = {}
        for p in ("firewallPolicies", "systemInterfaces", "systemZones"):
            fb, why = fortios_body(body.get(p))
            if why:
                return not_measured(validation, "FortiGate " + p + " read: " + why + ". Policies cannot be matched to "
                                    "internet-facing interfaces without it.",
                                    "The REST API administrator's profile needs read access to Firewall (policies) "
                                    "and Network (interfaces and zones).")
            rl = results_list(fb)
            if rl is None:
                return not_measured(validation, "FortiGate " + p + " read: the results are not a list of objects.")
            parsed[p] = (fb, rl)
        sdwan_body, sdwan_why = fortios_body(body.get("sdwan"))

        wan = set(["any", "virtual-wan-link", "sdwan"])
        known = set(["any", "virtual-wan-link", "sdwan"])
        for intf in parsed["systemInterfaces"][1]:
            n = str(intf.get("name") or "").strip().lower()
            if n == "":
                continue
            known.add(n)
            if str(intf.get("role") or "").strip().lower() == "wan":
                wan.add(n)
        for zone in parsed["systemZones"][1]:
            n = str(zone.get("name") or "").strip().lower()
            if n == "":
                continue
            known.add(n)
            members = lower_set(names(zone.get("interface")))
            for m in members:
                if m in wan:
                    wan.add(n)
        if sdwan_body is not None:
            sd = sdwan_body.get("results")
            sd_list = [sd] if isinstance(sd, dict) else (sd if isinstance(sd, list) else [])
            for s in sd_list:
                if not isinstance(s, dict):
                    continue
                for z in names(s.get("zone")):
                    known.add(z.lower())
                    wan.add(z.lower())

        policies = parsed["firewallPolicies"][1]
        vdom = str(parsed["firewallPolicies"][0].get("vdom") or "the token's VDOM")[:40]
        permissive = []
        unresolved = []
        for pol in policies:
            if str(pol.get("status") or "enable").strip().lower() != "enable":
                continue
            if str(pol.get("action") or "").strip().lower() != "accept":
                continue
            if str(pol.get("internet-service") or "disable").strip().lower() == "enable":
                continue
            if str(pol.get("service-negate") or "disable").strip().lower() == "enable":
                continue
            services = lower_set(names(pol.get("service")))
            dst4 = lower_set(names(pol.get("dstaddr")))
            dst6 = lower_set(names(pol.get("dstaddr6")))
            if str(pol.get("dstaddr-negate") or "disable").strip().lower() == "enable":
                dst4 = set()
            if str(pol.get("dstaddr6-negate") or "disable").strip().lower() == "enable":
                dst6 = set()
            if "all" not in services or ("all" not in dst4 and "all" not in dst6):
                continue
            label = "policy " + str(pol.get("policyid") or "?") + (" '" + str(pol.get("name"))[:60] + "'" if pol.get("name") else "")
            dst_intf = lower_set(names(pol.get("dstintf")))
            src_intf = lower_set(names(pol.get("srcintf")))
            unknown = [n for n in dst_intf if n not in known]
            to_wan = [n for n in dst_intf if n in wan]
            from_internal = [n for n in src_intf if n not in wan or n == "any"]
            if to_wan:
                if from_internal or len(src_intf) == 0:
                    permissive.append(label + " (" + ",".join(sorted(src_intf))[:60] + " -> " + ",".join(sorted(dst_intf))[:60] + ")")
                continue
            if (unknown or len(dst_intf) == 0) and (from_internal or len(src_intf) == 0):
                unresolved.append(label + " (destination interface " + (",".join(sorted(unknown)) or "none") + ")")
        summary = {"vdom": vdom, "policiesRead": len(policies), "internetFacingInterfaces": sorted(wan)[:MAX_NAMED],
                   "permissivePolicies": permissive[:MAX_NAMED], "unresolvedPolicies": unresolved[:MAX_NAMED],
                   "sdwanRead": sdwan_body is not None}
        if len(policies) == 0:
            return not_measured(validation, "FortiGate (VDOM " + vdom + ") returned no firewall policy. A FortiGate "
                                "with no policy passes no traffic, but an empty list cannot be told apart from a read "
                                "the token is not allowed to see in full.", None, summary)
        if permissive:
            extra = ""
            if unresolved:
                extra = ("; " + str(len(unresolved)) + " more accept-all polic(ies) go to an interface or zone that was "
                         "not read and may add to this count: " + name_list(unresolved))
            return create_response(
                result={KEY: len(permissive)},
                validation=validation,
                fail_reasons=["FortiGate (VDOM " + vdom + "): " + str(len(permissive)) + " of " + str(len(policies)) +
                              " enabled polic(ies) accept every service (ALL) to any destination (all) on an internet-"
                              "facing interface: " + name_list(permissive) + extra + ". " + LIMITS],
                recommendations=["Replace service ALL with the services needed (for example HTTP, HTTPS and DNS to named "
                                 "resolvers) on each policy named, and keep any broad exception documented and scoped "
                                 "to named sources."],
                input_summary=summary,
            )
        if unresolved:
            return not_measured(validation, "FortiGate (VDOM " + vdom + "): " + str(len(unresolved)) + " accept-all "
                                "polic(ies) send traffic to an interface or zone that is not in the interface, zone or "
                                "SD-WAN read (" + name_list(unresolved) + "), so whether they reach the internet cannot "
                                "be shown.", None, summary)
        return create_response(
            result={KEY: 0},
            validation=validation,
            pass_reasons=["FortiGate (VDOM " + vdom + "): none of " + str(len(policies)) + " firewall policies accepts "
                          "service ALL to the any address on an internet-facing interface (" +
                          name_list(sorted(wan)) + "). " + LIMITS],
            input_summary=summary,
        )
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
