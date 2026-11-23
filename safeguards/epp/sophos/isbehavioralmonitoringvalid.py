"""
Transformation: isBehavioralMonitoringValid
Vendor: Sophos Central (Intercept X / Endpoint)  |  Category: Endpoint Security
Method: getThreatProtectionPolicies (proposed)
        GET /endpoint/v1/policies?policyType=threat-protection&pageTotal=true&pageSize=200
        The unfiltered getPolicies body (GET /endpoint/v1/policies) is also accepted:
        only items whose type is "threat-protection" are judged.

Evidence: the tenant's Threat Protection policies. Documented at
developer.sophos.com/endpoint-policies and /endpoint-policy-settings-all:
  { "items": [ { "id", "name", "type": "threat-protection", "priority", "enabled",
                 "settings": { "<key>": {"value": ...} }, "appliesTo": {...} } ],
    "pages": { "current", "size", "total", "items", "maxSize" } }
The Base Policy (priority 0, always enabled) applies to every user and endpoint not
assigned to another policy. Other policies override it for the users, user groups,
endpoints or endpoint groups listed in appliesTo.

A policy monitors behaviour when both of these are explicitly true in its settings:
  endpoint.threat-protection.malware-protection.on-access.enabled
      "Enable real-time scanning". Sophos documents that turning it off also disables
      detection of malicious behaviour, so it is required.
  endpoint.threat-protection.malware-protection.behavioral-detection.enabled
      "Detect malicious behavior".
      Legacy: when this key is absent and hips-detection.enabled ("Detect malicious
      behaviour (HIPS)", the feature Sophos is replacing with Behavioral Detection) is
      explicitly true, the policy is accepted and the fallback is reported.
      An explicit false on behavioral-detection fails the policy whatever HIPS says.
A required setting that is absent is NOT read at its documented default: the default is
not evidence of this tenant's configuration, so the policy fails with "not returned".

Verdict: true only when the Base Policy is present and monitors behaviour, and every
other enabled policy that is assigned to someone also does. Every Windows/macOS endpoint
is then governed by a policy that detects malicious behaviour. Disabled policies, and
enabled policies whose appliesTo lists are all empty, govern no one and are not judged.

What this proves: Sophos is configured to run real-time scanning and behavioural
detection on every endpoint it manages through a Threat Protection policy. What it does
not prove: server policies (server-threat-protection is a separate type and not read),
that each endpoint's agent is healthy or has received the policy (that is endpoint
health in /endpoint/v1/endpoints, not read here), or devices Sophos does not manage.

Fails closed: an error response, an empty, None or unrecognised body, a policy list that
spans more than one page (only page 1 is read) or whose full first page carries no page
total, no Threat Protection policy, or no Base Policy all return false.
"""
import json
from datetime import datetime


CRITERIA_KEY = "isBehavioralMonitoringValid"
POLICY_TYPE = "threat-protection"
ON_ACCESS_KEY = "endpoint.threat-protection.malware-protection.on-access.enabled"
BEHAVIOURAL_KEY = "endpoint.threat-protection.malware-protection.behavioral-detection.enabled"
HIPS_KEY = "endpoint.threat-protection.malware-protection.hips-detection.enabled"
AMSI_KEY = "endpoint.threat-protection.malware-protection.amsi-protection.enabled"
C2_KEY = "endpoint.threat-protection.network-protection.c2-detection.enabled"
ASSIGNMENT_FIELDS = ("users", "userGroups", "endpoints", "endpointGroups")
ERROR_KEYS = ("error", "errors", "errorMessage", "errorType", "fault")


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
            "dataCollection": {"status": "error" if (api_errors or []) else "success",
                               "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"),
                           "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [],
                               "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [],
                           "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": CRITERIA_KEY, "vendor": "Sophos",
                         "category": "Endpoint Security"},
        },
    }


def api_error_message(data):
    """A short, non-sensitive description of an error body, or None."""
    if not isinstance(data, dict):
        return None
    for key in ERROR_KEYS:
        value = data.get(key)
        if value:
            if isinstance(value, str):
                return "Sophos API returned an error: " + value[:120]
            return "Sophos API returned an error"
    for key in ("statusCode", "status_code", "status", "code"):
        value = data.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 400:
            return "Sophos API returned HTTP " + str(value)
        if isinstance(value, str) and value.strip().lower() in ("error", "failed", "failure"):
            return "Sophos API returned status " + value.strip()[:40]
    return None


def policy_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return items
    return None


def extra_pages(data, item_count):
    """Pages beyond the first that were not read: 0 when the list is complete, -1 when
    completeness cannot be shown (no page total and the first page is full)."""
    if not isinstance(data, dict):
        return 0
    pages = data.get("pages")
    if not isinstance(pages, dict):
        return 0
    total = pages.get("total")
    if isinstance(total, int) and not isinstance(total, bool):
        if total > 1:
            return total - 1
        return 0
    size = pages.get("size")
    if isinstance(size, int) and not isinstance(size, bool) and size > 0 and item_count >= size:
        return -1
    return 0


def explicit_bool(settings, key):
    """True / False when the setting is present as a boolean (or "true"/"false"), else None."""
    if not isinstance(settings, dict) or key not in settings:
        return None
    entry = settings.get(key)
    if isinstance(entry, dict):
        if "value" not in entry:
            return None
        entry = entry.get("value")
    if entry is True or entry is False:
        return entry
    if isinstance(entry, str):
        lowered = entry.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def is_truthy(value):
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


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


def policy_name(policy):
    return str(policy.get("name") or policy.get("id") or "unnamed")[:80]


def judge_policy(policy):
    """Returns (problems, used_hips_fallback)."""
    settings = policy.get("settings")
    if not isinstance(settings, dict) or not settings:
        return ["no settings returned"], False
    problems = []
    on_access = explicit_bool(settings, ON_ACCESS_KEY)
    if on_access is None:
        problems.append("real-time scanning setting not returned")
    elif on_access is False:
        problems.append("real-time scanning is off (behaviour detection is disabled with it)")
    behavioural = explicit_bool(settings, BEHAVIOURAL_KEY)
    used_hips = False
    if behavioural is False:
        problems.append("Detect malicious behavior is off")
    elif behavioural is None:
        hips = explicit_bool(settings, HIPS_KEY)
        if hips is True:
            used_hips = True
        elif hips is False:
            problems.append("Detect malicious behaviour (HIPS) is off and Behavioral Detection is not returned")
        else:
            problems.append("behaviour detection setting not returned")
    return problems, used_hips


def transform(input):
    criteriaKey = CRITERIA_KEY
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            text = input.decode("utf-8")
            input = json.loads(text) if text.strip() else None

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])

        error = api_error_message(data)
        items = policy_items(data)
        if error or items is None:
            reason = error or "Threat Protection policy response not recognised - no items list present"
            return create_response(
                result={criteriaKey: False}, validation=validation,
                api_errors=[reason], fail_reasons=[reason],
                recommendations=["Verify the Sophos policies API (/endpoint/v1/policies) is reachable and the credential can read endpoint policies"])

        unread = extra_pages(data, len(items))
        if unread != 0:
            if unread > 0:
                reason = "The policy list spans " + str(unread + 1) + " pages and only the first was read"
            else:
                reason = "The first page of policies is full and no page total was returned, so the list may be incomplete"
            return create_response(
                result={criteriaKey: False}, validation=validation,
                api_errors=[reason], fail_reasons=[reason],
                recommendations=["Read Threat Protection policies with policyType=threat-protection and page-based pagination"])

        policies = [p for p in items if isinstance(p, dict) and p.get("type") == POLICY_TYPE]
        base = [p for p in policies if is_base(p)]
        judged = []
        not_applied = 0
        for policy in policies:
            if is_base(policy) or (is_truthy(policy.get("enabled")) and is_assigned(policy)):
                judged.append(policy)
            else:
                not_applied = not_applied + 1

        failing = []
        hips_fallback = []
        optional_off = []
        for policy in judged:
            problems, used_hips = judge_policy(policy)
            name = policy_name(policy)
            if problems:
                failing.append(name + ": " + "; ".join(problems))
            if used_hips:
                hips_fallback.append(name)
            settings = policy.get("settings") if isinstance(policy.get("settings"), dict) else {}
            if explicit_bool(settings, AMSI_KEY) is False:
                optional_off.append(name + ": AMSI protection is off")
            if explicit_bool(settings, C2_KEY) is False:
                optional_off.append(name + ": command-and-control detection is off")

        value = len(policies) > 0 and len(base) > 0 and len(failing) == 0
        summary = {
            "threatProtectionPolicies": len(policies),
            "policiesJudged": len(judged),
            "policiesNotApplied": not_applied,
            "basePolicyFound": len(base) > 0,
            "policiesNotMonitoringBehaviour": failing[:20],
            "policiesOnLegacyHips": hips_fallback[:20],
        }

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []
        if not policies:
            fail_reasons.append("No Threat Protection policy was returned, so no endpoint is shown to have behaviour detection")
            recommendations.append("Check that the Sophos Central credential can read endpoint policies and that the method requests policyType=threat-protection")
        elif not base:
            fail_reasons.append("No Threat Protection Base Policy was returned, so the policy for unassigned endpoints is unknown")
            recommendations.append("Check that the Sophos Central credential can read every endpoint policy")
        if failing:
            fail_reasons.append(str(len(failing)) + " applied Threat Protection polic(ies) do not monitor behaviour: " + " | ".join(failing[:10]))
            recommendations.append("In Sophos Central, turn on real-time scanning and Detect malicious behavior in every applied Threat Protection policy, including the Base Policy")
        if value:
            pass_reasons.append("All " + str(len(judged)) + " applied Threat Protection polic(ies), including the Base Policy, have real-time scanning and behaviour detection on")
        if hips_fallback:
            findings.append(str(len(hips_fallback)) + " polic(ies) were accepted on the legacy HIPS setting because Behavioral Detection was not returned: " + ", ".join(hips_fallback[:10]))
        if optional_off:
            findings.append("Related protections off (not judged): " + " | ".join(optional_off[:10]))
        findings.append("Server Threat Protection policies and per-endpoint agent health are not read by this check")

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, additional_findings=findings,
                               input_summary={criteriaKey: value, **summary})
    except Exception as e:
        # The evaluator reads additionalInfo.dataCollection.status only, which is derived
        # from api_errors; the transformation channel alone leaves the row graded as a
        # measured answer. Report the failure on both so the row reads Not evaluated.
        reason = "Transformation error: " + str(e)[:200]
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)[:200]],
                               api_errors=[reason],
                               fail_reasons=[reason])
