"""
Transformation: firewall_transform
Vendor: Cisco Secure Firewall Management Center (FMC REST API)  |  Category: Network Security / Firewall
Answers: isFirewallEnabled
Source: GET {baseURL}/api/fmc_config/v1/domain/{domainUUID}/assignment/policyassignments?expanded=true
(the definition's getPolicyAssignments method). Body: {"links", "items": [PolicyAssignment, ...], "paging": {"offset",
"limit", "count", "pages"}}, each item {"type": "PolicyAssignment", "id", "policy": {"type": "AccessPolicy", "name",
"id"}, "targets": [{"type": "Device", "id", "name"}]}. Without expanded=true FMC lists only a reference per item.

isFirewallEnabled: at least one access control policy (policy.type AccessPolicy) is assigned to at least one managed
device. An FMC enforces traffic through the access control policy assigned to each device ("You can assign only one
policy to a device"), so a device with none assigned is not being firewalled by this FMC. Assignments read with none
of them an access control policy on a device is False.

Not evaluated (every key routed here None, with a dataCollection error): an empty, error or unrecognised body; no
assignment at all; items without policy and targets (the list was read without expanded=true); a partial page that
shows no access control policy on a device; or any other FMC body. That includes the management audit log
(getAuditLogging), which this file used to be wired to: audit records describe administrator activity on the FMC and
say nothing about whether a firewall is enforcing traffic.

Previously this file read isFirewallEnabled out of the response, then set it True whenever the body had an "items"
key. Wired to the audit log, that graded every FMC as firewall-enabled, including one with an empty audit log, and set
isFirewallLoggingEnabled from whether any audit record existed. isFirewallLoggingEnabled and isFirewallUpdated are no
longer answered here; see the C1a validation record for their definition rows.
"""
import json
from datetime import datetime, timezone

KEY = "isFirewallEnabled"

#: keys the definition routes to this file that its body cannot answer; None on the not-measured path
ROUTED_HERE = ("isFirewallEnabled", "isFirewallLoggingEnabled", "isFirewallUpdated")

WRAPPERS = ("apiResponse", "api_response", "rawResponse", "response", "result", "Output")

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
                "vendor": "Cisco FMC",
                "category": "Network Security",
            },
        },
    }


def not_measured(validation, reason, summary=None, transformation_errors=None):
    """Every routed key None: reads Not evaluated, never True or False."""
    result = {}
    for k in ROUTED_HERE:
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
    """A short reason when obj is an FMC or platform error envelope, else None."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if isinstance(err, dict):
        messages = err.get("messages")
        first = messages[0] if isinstance(messages, list) and messages else {}
        detail = first.get("description") if isinstance(first, dict) else first
        return "FMC returned an error: " + str(detail or err.get("category") or "error")[:200]
    if err is True or isinstance(err, str):
        return "the call did not return data: " + str(obj.get("message") or err)[:300]
    for name in ("statusCode", "status_code"):
        code = as_int(obj.get(name))
        if code is not None and code >= 400:
            return "the call returned HTTP " + str(code)
    vendor = obj.get("vendorErrorAsResponse")
    if isinstance(vendor, dict):
        return "the call returned " + str(vendor.get("status") or "an error") + ": " + str(vendor.get("message"))[:200]
    return None


def fmc_collection(raw):
    """(body, None) for an FMC collection body with an items list, else (None, reason)."""
    cur = to_obj(raw)
    for depth in range(6):
        if cur is None:
            return None, "the response body is empty; nothing was read from the FMC"
        if not isinstance(cur, dict):
            return None, "the response is not a JSON object"
        why = envelope_error(cur)
        if why:
            return None, why
        if isinstance(cur.get("items"), list):
            return cur, None
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None:
            break
        cur = nxt
    return None, "the response carries no FMC items list"


def is_assignment(item):
    return isinstance(item, dict) and (item.get("type") == "PolicyAssignment" or "targets" in item)


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

        body, why = fmc_collection(raw)
        if why:
            return not_measured(validation, "Cisco FMC policy assignment read: " + why + ".")

        items = body.get("items")
        if len(items) == 0:
            return not_measured(validation, "Cisco FMC returned no policy assignment. An empty list cannot be told "
                                "apart from a domain or user that does not see the managed devices.",
                                {"assignmentsRead": 0})

        assignments = [i for i in items if is_assignment(i)]
        if len(assignments) == 0:
            kinds = sorted(set(str(i.get("type") if isinstance(i, dict) else "non-object") for i in items))
            return not_measured(validation, "Cisco FMC: the response is not the policy assignment list (item type " +
                                ", ".join(kinds)[:120] + "). An audit log or any other FMC list does not show "
                                "whether a firewall policy is enforcing traffic.", {"itemTypes": kinds[:10]})

        enforcing = []
        devices = []
        other_policies = 0
        unexpanded = 0
        for a in assignments:
            policy = a.get("policy")
            targets = a.get("targets")
            if not isinstance(policy, dict) or not isinstance(targets, list):
                unexpanded = unexpanded + 1
                continue
            if policy.get("type") != "AccessPolicy":
                other_policies = other_policies + 1
                continue
            if len(targets) == 0:
                continue
            enforcing.append("'" + str(policy.get("name") or policy.get("id") or "?")[:60] + "' on " +
                             str(len(targets)) + " device(s)")
            for t in targets:
                if isinstance(t, dict):
                    devices.append(str(t.get("name") or t.get("id") or "?")[:60])

        paging = body.get("paging") if isinstance(body.get("paging"), dict) else {}
        count = as_int(paging.get("count"))
        partial = count is not None and count > len(items)
        summary = {"assignmentsRead": len(assignments), "accessPoliciesOnDevices": len(enforcing),
                   "devicesWithAccessPolicy": len(devices), "otherPolicyAssignments": other_policies,
                   "assignmentsWithoutDetail": unexpanded, "partialRead": partial}

        if enforcing:
            return create_response(
                {KEY: True}, validation,
                pass_reasons=["Cisco FMC: an access control policy is assigned to " + str(len(devices)) +
                              " managed device(s): " + name_list(enforcing) + "."],
                input_summary=summary)
        if unexpanded:
            return not_measured(validation, "Cisco FMC: " + str(unexpanded) + " policy assignment(s) were listed "
                                "without their policy and targets; the list must be read with expanded=true.", summary)
        if partial:
            return not_measured(validation, "Cisco FMC: the first page of " + str(len(items)) + " of " + str(count) +
                                " policy assignments has no access control policy on a device.", summary)
        return create_response(
            {KEY: False}, validation,
            fail_reasons=["Cisco FMC: none of " + str(len(assignments)) + " policy assignments puts an access "
                          "control policy on a managed device."],
            recommendations=["Assign an access control policy to every managed device and deploy it."],
            input_summary=summary)

    except Exception as e:
        message = "Transformation error: " + str(e)[:300]
        return not_measured(validation, message, transformation_errors=[message])
