"""
Transformation: isRemovableMediaControlled
Vendor: Sophos Central (Intercept X / Endpoint)  |  Category: Endpoint Security
Method: getPeripheralControlPolicies
        (GET /endpoint/v1/policies?policyType=peripheral-control&pageTotal=true)

Evidence: the tenant's Peripheral Control policies. Documented at
developer.sophos.com/endpoint-policies and /endpoint-policy-settings-all:
  { "items": [ { "id", "name", "type": "peripheral-control", "priority", "enabled",
                 "settings": { "<key>": {"value": ...} }, "appliesTo": {...} } ],
    "pages": { "current", "size", "total", "items", "maxSize" } }
The Base Policy (priority 0, always enabled) applies to every user and endpoint not
assigned to another policy. Other policies override it for the users, user groups,
endpoints or endpoint groups listed in appliesTo.

A policy restricts removable media when all of these hold:
  endpoint.peripheral-control.enabled                  == true   (default false)
  endpoint.peripheral-control.monitor                  != true   (true = "monitor but
                                                                  do not block")
  endpoint.peripheral-control.actions.removable-storage in ("blocked", "readOnly")
                                                                  (default "allowed")
A setting that is absent is read at its documented default.

Verdict: true only when the Base Policy is present and restricts, and every other
enabled policy that is assigned to someone also restricts. Every endpoint is then
governed by a restricting policy. Disabled policies, and enabled policies whose
appliesTo lists are all empty, govern no one and are not judged.

What this proves: Sophos is configured to block (or make read-only) removable storage
on every Windows/macOS endpoint it manages. What it does not prove: server policies
(server-peripheral-control is a separate type and not read), secure (hardware-encrypted)
removable storage, which is left to the customer, or devices Sophos does not manage.
Per-device exemptions are reported, not judged.

Fails closed: a policy list that spans more than one page (only page 1 is read), an
error response, an empty or unrecognised body, or no Base Policy all return false.
"""
import json
from datetime import datetime


POLICY_TYPE = "peripheral-control"
ENABLED_KEY = "endpoint.peripheral-control.enabled"
MONITOR_KEY = "endpoint.peripheral-control.monitor"
REMOVABLE_KEY = "endpoint.peripheral-control.actions.removable-storage"
EXEMPTIONS_KEY = "endpoint.peripheral-control.exemptions"
RESTRICTIVE_ACTIONS = ("blocked", "readOnly")
ASSIGNMENT_FIELDS = ("users", "userGroups", "endpoints", "endpointGroups")


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRemovableMediaControlled", "vendor": "Sophos", "category": "Endpoint Security"}
        }
    }


def api_error_message(data):
    if isinstance(data, dict) and (data.get("error") is True or str(data.get("error")).lower() == "true"):
        return str(data.get("errorMessage") or data.get("message") or "Sophos API returned an error")
    if isinstance(data, dict) and str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Sophos API returned an error")
    return None


def policy_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return items
    return None


def extra_pages(data):
    """Number of pages beyond the first that were not read, or 0."""
    if not isinstance(data, dict):
        return 0
    pages = data.get("pages")
    if not isinstance(pages, dict):
        return 0
    total = pages.get("total")
    if isinstance(total, int) and total > 1:
        return total - 1
    return 0


def truthy(value):
    return value is True or str(value).lower() == "true"


def setting_value(settings, key, default):
    entry = settings.get(key) if isinstance(settings, dict) else None
    if isinstance(entry, dict):
        if "value" in entry:
            return entry.get("value")
        return default
    if entry is None:
        return default
    return entry


def is_base(policy):
    return str(policy.get("priority")) == "0"


def is_assigned(policy):
    """False only when appliesTo is present and every assignment list is empty."""
    applies = policy.get("appliesTo")
    if not isinstance(applies, dict):
        return True
    for field in ASSIGNMENT_FIELDS:
        members = applies.get(field)
        if isinstance(members, list) and len(members) > 0:
            return True
    return False


def restriction_problems(policy):
    settings = policy.get("settings")
    if not isinstance(settings, dict):
        return ["no settings returned"]
    problems = []
    if not truthy(setting_value(settings, ENABLED_KEY, False)):
        problems.append("peripheral control is off")
    if truthy(setting_value(settings, MONITOR_KEY, False)):
        problems.append("monitor-only mode (nothing is blocked)")
    action = setting_value(settings, REMOVABLE_KEY, "allowed")
    if action not in RESTRICTIVE_ACTIONS:
        problems.append(f"removable storage is '{action}'")
    return problems


def transform(input):
    criteriaKey = "isRemovableMediaControlled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])

        error = api_error_message(data)
        items = policy_items(data)
        if error or items is None:
            reason = error or "Peripheral Control policy response not recognised - no items list present"
            return create_response(result={criteriaKey: False}, validation=validation,
                                   api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Verify the Sophos policies API (/endpoint/v1/policies) is reachable and the credential can read policies"])

        unread = extra_pages(data)
        if unread > 0:
            reason = f"The Peripheral Control policy list spans {unread + 1} pages and only the first was read"
            return create_response(result={criteriaKey: False}, validation=validation,
                                   api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Add page-based pagination to getPeripheralControlPolicies"])

        policies = [p for p in items if isinstance(p, dict) and p.get("type") == POLICY_TYPE]
        base = [p for p in policies if is_base(p)]
        judged = []
        not_judged = 0
        for policy in policies:
            if is_base(policy) or (truthy(policy.get("enabled")) and is_assigned(policy)):
                judged.append(policy)
            else:
                not_judged = not_judged + 1

        failing = []
        exemptions = 0
        for policy in judged:
            problems = restriction_problems(policy)
            name = str(policy.get("name") or policy.get("id") or "unnamed")
            if problems:
                failing.append(name + ": " + "; ".join(problems))
            listed = setting_value(policy.get("settings") or {}, EXEMPTIONS_KEY, [])
            if isinstance(listed, list):
                exemptions = exemptions + len(listed)

        value = len(base) > 0 and len(failing) == 0
        summary = {
            "peripheralControlPolicies": len(policies),
            "policiesJudged": len(judged),
            "policiesNotApplied": not_judged,
            "basePolicyFound": len(base) > 0,
            "policiesNotRestricting": failing[:20],
            "deviceExemptions": exemptions,
        }

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []
        if not base:
            fail_reasons.append("No Peripheral Control Base Policy was returned, so the default for unassigned endpoints is unknown")
            recommendations.append("Check that the Sophos Central credential can read endpoint policies")
        if failing:
            fail_reasons.append(f"{len(failing)} applied Peripheral Control polic(ies) do not block removable storage: " + " | ".join(failing[:10]))
            recommendations.append("In Sophos Central, turn on Peripheral Control, turn off monitor-only mode, and set Removable storage to Block or Read only in every applied policy")
        if value:
            pass_reasons.append(f"All {len(judged)} applied Peripheral Control polic(ies), including the Base Policy, block or make read-only removable storage")
        if exemptions:
            findings.append(f"{exemptions} per-device exemption(s) are configured and were not judged")

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, additional_findings=findings,
                               input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
