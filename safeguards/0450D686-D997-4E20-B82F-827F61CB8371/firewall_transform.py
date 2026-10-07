"""
Transformation: firewall_transform
Vendor: Fortinet FortiGate (FortiOS REST API)  |  Category: Network Security / Firewall
Answers: isFirewallEnabled, isFirewallLoggingEnabled, isFirewallConfigured
Source: getFirewallPolicies, GET {baseUrl}/api/v2/cmdb/firewall/policy. Integration-Service returns the FortiOS
body under apiResponse (returnSpec rawResponse) beside "policies", which defaults to [] when the call fails and is
therefore never read on its own. FortiOS body: {"http_method": "GET", "results": [...], "vdom", "status": "success",
"http_status": 200}.

Fields read, per the FortiOS CLI reference for config firewall policy (the cmdb object carries the same attributes):
    status      enable | disable, default enable  -- "Enable or disable this policy."
    logtraffic  all | utm | disable, default utm  -- all: "Log all sessions accepted or denied by this policy";
                utm: "Log traffic that has a security profile applied to it"; disable: "Disable all logging for this
                policy."

isFirewallEnabled: at least one firewall policy is enabled. Every policy disabled is False.
isFirewallLoggingEnabled: every enabled policy logs (logtraffic all or utm). utm logs only sessions a security
profile inspects, and the reason says how many policies log at that level. A policy without logtraffic is read at
its documented default, utm.
isFirewallConfigured: both of the above.

Not evaluated (every key None with a dataCollection error): an empty, error or unrecognised body; FortiOS not
reporting success; a partial read (matched_count above the results returned); or no policy at all, because an empty
list cannot be told apart from a read the token's VDOM or admin profile does not show in full.
Scope: the API token's VDOM, consolidated policy table only.

Previously this file read isFirewallEnabled and isFirewallLoggingEnabled as fields of the FortiOS body. FortiOS sends
neither, so both were False for every FortiGate.
"""
import json
from datetime import datetime, timezone

KEYS = ("isFirewallEnabled", "isFirewallLoggingEnabled", "isFirewallConfigured")

WRAPPERS = ("apiResponse", "api_response", "rawResponse", "response", "result", "Output")

LOGGING_LEVELS = ("all", "utm")

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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None):
    """Standardized transformation response. dataCollection is derived from the values: a key left None was not
    measured, so the status is "error" and Token-Service records Not evaluated rather than Failed."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    unmeasured = [k for k in result if result[k] is None]
    api_errors = []
    if unmeasured:
        api_errors = (fail_reasons or [])[:1] or ["not measured: " + ", ".join(unmeasured)]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": "firewall_transform",
                "vendor": "Fortinet FortiGate",
                "category": "Network Security",
            },
        },
    }


def not_measured(validation, reason, summary=None, transformation_errors=None):
    """Every key None: reads Not evaluated, never True or False."""
    result = {}
    for k in KEYS:
        result[k] = None
    return create_response(result, validation, fail_reasons=[reason], input_summary=summary,
                           transformation_errors=transformation_errors)


def as_int(value):
    """A whole number from an int or a digit string, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


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
    for name in ("statusCode", "status_code"):
        code = as_int(obj.get(name))
        if code is not None and code >= 400:
            return "the call returned HTTP " + str(code)
    vendor = obj.get("vendorErrorAsResponse")
    if isinstance(vendor, dict):
        return "the call returned " + str(vendor.get("status") or "an error") + ": " + str(vendor.get("message"))[:200]
    return None


def fortios_body(raw):
    """(body, None) for a successful FortiOS cmdb read, else (None, reason)."""
    cur = to_obj(raw)
    for depth in range(6):
        if cur is None:
            return None, "the response body is empty; nothing was read from the FortiGate"
        if not isinstance(cur, dict):
            return None, "the response is not a JSON object"
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
            return None, "the response carries no FortiOS results (not the firewall/policy body)"
        cur = nxt
    if not (isinstance(cur, dict) and "results" in cur):
        return None, "the response carries no FortiOS results (not the firewall/policy body)"
    status = str(cur.get("status") or "").strip().lower()
    http_status = as_int(cur.get("http_status"))
    if status not in ("", "success") or (http_status is not None and http_status != 200):
        return None, "FortiOS answered status " + str(cur.get("status")) + " (HTTP " + str(cur.get("http_status")) + ")"
    if status == "" and http_status is None:
        return None, "the FortiOS body carries neither status nor http_status, so success cannot be shown"
    results = cur.get("results")
    if isinstance(results, dict):
        results = [results]
    if not isinstance(results, list):
        return None, "the FortiOS results are not a list"
    for r in results:
        if not isinstance(r, dict):
            return None, "the FortiOS results are not a list of policy objects"
    # next_idx is sent on complete FortiOS 7.x reads too, so only matched_count marks a partial read.
    matched = as_int(cur.get("matched_count"))
    if matched is not None and matched > len(results):
        return None, ("a partial read: FortiOS matched " + str(matched) + " policies and returned " + str(len(results)))
    return {"vdom": cur.get("vdom"), "policies": results}, None


def label(pol):
    name = pol.get("name")
    return "policy " + str(pol.get("policyid") or "?") + (" '" + str(name)[:60] + "'" if name else "")


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def transform(input):
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
            raw = input.get("data")
        else:
            raw = input

        if validation.get("status") == "failed":
            return not_measured(validation, "Input validation failed: nothing was measured.")

        body, why = fortios_body(raw)
        if why:
            return not_measured(validation, "FortiGate firewall policy read: " + why + ".")

        policies = body["policies"]
        vdom = str(body.get("vdom") or "the token's VDOM")[:40]
        if len(policies) == 0:
            return not_measured(validation, "FortiGate (VDOM " + vdom + ") returned no firewall policy. An empty list "
                                "cannot be told apart from a read the token is not allowed to see in full.",
                                {"vdom": vdom, "policiesRead": 0})

        enabled = []
        disabled = []
        not_logging = []
        utm_only = []
        for pol in policies:
            if str(pol.get("status") or "enable").strip().lower() != "enable":
                disabled.append(label(pol))
                continue
            enabled.append(label(pol))
            level = str(pol.get("logtraffic") or "utm").strip().lower()
            if level not in LOGGING_LEVELS:
                not_logging.append(label(pol) + " (logtraffic " + level + ")")
            elif level == "utm":
                utm_only.append(label(pol))

        is_enabled = len(enabled) > 0
        is_logging = is_enabled and len(not_logging) == 0
        result = {
            "isFirewallEnabled": is_enabled,
            "isFirewallLoggingEnabled": is_logging,
            "isFirewallConfigured": is_enabled and is_logging,
        }
        summary = {"vdom": vdom, "policiesRead": len(policies), "enabledPolicies": len(enabled),
                   "disabledPolicies": len(disabled), "policiesNotLogging": not_logging[:MAX_NAMED],
                   "policiesLoggingSecurityProfileSessionsOnly": len(utm_only)}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_enabled:
            pass_reasons.append("FortiGate (VDOM " + vdom + "): " + str(len(enabled)) + " of " + str(len(policies)) +
                                " firewall policies are enabled.")
        else:
            fail_reasons.append("FortiGate (VDOM " + vdom + "): all " + str(len(policies)) + " firewall policies are "
                                "disabled: " + name_list(disabled) + ".")
            recommendations.append("Enable the firewall policies that should be enforcing traffic.")
        if is_logging:
            extra = ""
            if utm_only:
                extra = (" " + str(len(utm_only)) + " of them log at utm, which records only sessions a security "
                         "profile inspects.")
            pass_reasons.append("FortiGate (VDOM " + vdom + "): every enabled policy logs traffic (logtraffic all or "
                                "utm)." + extra)
        elif is_enabled:
            fail_reasons.append("FortiGate (VDOM " + vdom + "): " + str(len(not_logging)) + " enabled polic(ies) have "
                                "traffic logging disabled: " + name_list(not_logging) + ".")
            recommendations.append("Set logtraffic to all (or utm) on every enabled firewall policy.")

        return create_response(result, validation, pass_reasons, fail_reasons, recommendations, summary)

    except Exception as e:
        message = "Transformation error: " + str(e)[:300]
        return not_measured(validation, message, transformation_errors=[message])
