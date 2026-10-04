"""
Transformation: isEPPConfigured
Vendor: Trend Micro Vision One (Endpoint Security)  |  Category: Endpoint Security
Method: getEndpointSecurityEndpoints (GET {serverUrl}/v3.0/endpointSecurity/endpoints, nextLink pagination)

Evidence: the Endpoint Inventory list (response model: trendmicro/tm-v1-pytv1 EndpointSecurityEndpoint,
EppAgent, EdrSensor; field values: trendmicro/vision-one-mcp-server FilterEndpoints table).
Confirmed on a real customer payload (2026-09-25).

Value: a whole-number percentage, floor(100 * configured / protected). protected = endpoints with an
installed protection agent (servers included); configured = those agents that name the policy their
protection manager applied (eppAgent.policyName, "the name of a policy from your protection
manager"). Endpoints without an agent are coverage (requiredCoveragePercentage), not configuration.
The pass bar lives in the requirement; sensor last-connected age is not read.

What this proves: every agent reports an applied protection policy. What it does not prove:
what that policy enables.

Unmeasured agents: Vision One does not receive the policy of agents managed by Trend Micro
Worry-Free Business Security (eppAgent.protectionManager names Worry-Free; policyName is empty
for all of them on real payloads). Such an agent with no policyName is not visible, not
unconfigured. Fail-closed handling of unmeasured agents (never a pass on partial data):
  * no unmeasured agent: the percentage over all protected agents, as before;
  * unmeasured agents and no measured agent without a policy: None (Not evaluated), with the
    unmeasured count and the measured coverage in the result;
  * unmeasured agents and at least one measured agent without a policy: a lower bound that counts
    every unmeasured agent as not configured, so it can only meet a bar it would meet in the worst
    case.

Not evaluated (dataCollection error, no value): an error body, an unrecognised body, an empty
endpoint list, no installed protection agent, or a merged response that still carries nextLink
(pages left unread).
"""
import json
from datetime import datetime


VENDOR = "Trend Micro"
CATEGORY = "Endpoint Security"


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


def create_response(criteria_key, result, validation=None, pass_reasons=None, fail_reasons=None,
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": criteria_key, "vendor": VENDOR, "category": CATEGORY}
        }
    }


def api_error_message(data):
    """Vision One errors are {"error": {"code", "message"}}; Integration-Service errors carry status Error."""
    if not isinstance(data, dict):
        return None
    err = data.get("error")
    if isinstance(err, dict):
        return "Trend Vision One API error " + str(err.get("code") or "") + ": " + str(err.get("message") or "")
    if err is True or str(err).lower() == "true":
        return str(data.get("errorMessage") or data.get("message") or "Trend Vision One API returned an error")
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or data.get("errorMessage") or "Trend Vision One API returned an error")
    return None


def endpoint_items(data):
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [e for e in items if isinstance(e, dict)]
    return None


def unread_pages(data):
    """True when the merged response still carries a nextLink: pagination stopped early."""
    if isinstance(data, dict):
        link = data.get("nextLink")
        return isinstance(link, str) and link != ""
    return False


def endpoint_name(endpoint):
    return str(endpoint.get("endpointName") or endpoint.get("displayName") or endpoint.get("agentGuid") or "unnamed")


def sub(endpoint, key):
    block = endpoint.get(key)
    return block if isinstance(block, dict) else None


def load_endpoints(criteria_key, input, fail_value):
    """Returns (endpoints, validation, None) or (None, None, failure_response)."""
    if isinstance(input, str):
        input = json.loads(input)
    elif isinstance(input, bytes):
        input = json.loads(input.decode("utf-8"))
    data, validation = extract_input(input)
    if validation.get("status") == "failed":
        return None, None, create_response(criteria_key, {criteria_key: fail_value}, validation=validation,
                                           fail_reasons=["Input validation failed"])
    error = api_error_message(data)
    items = endpoint_items(data)
    if error or items is None:
        reason = error or "Endpoint list response not recognised - no items list present"
        return None, None, create_response(criteria_key, {criteria_key: fail_value}, validation=validation,
                                           api_errors=[reason], fail_reasons=[reason],
                                           recommendations=["Verify the API key can call GET /v3.0/endpointSecurity/endpoints (Endpoint Inventory: View) and that serverUrl is the tenant's regional API domain"])
    if unread_pages(data):
        reason = "The endpoint list has more pages than were read (nextLink still present)"
        return None, None, create_response(criteria_key, {criteria_key: fail_value}, validation=validation,
                                           api_errors=[reason], fail_reasons=[reason],
                                           recommendations=["Raise maxPages on getEndpointSecurityEndpoints"])
    if len(items) == 0:
        reason = "Trend Vision One returned no endpoints, so nothing about the estate is proven"
        return None, None, create_response(criteria_key, {criteria_key: fail_value}, validation=validation,
                                           api_errors=[reason], fail_reasons=[reason],
                                           recommendations=["Confirm endpoints are managed in Trend Vision One Endpoint Inventory and that the API key's role can see them"])
    return items, validation, None


def failure(criteria_key, fail_value, error):
    return create_response(criteria_key, {criteria_key: fail_value},
                           validation={"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[str(error)], fail_reasons=["Transformation error: " + str(error)])


def has_protection_agent(endpoint):
    """An eppAgent block with neither a version nor a protection manager is a placeholder
    Vision One writes for sensor-only endpoints (real payload: 21 of 417, status off/unknown),
    not an installed protection agent."""
    agent = sub(endpoint, "eppAgent")
    if agent is None:
        return False
    return bool(str(agent.get("version") or "").strip() or str(agent.get("protectionManager") or "").strip())


def policy_not_reported(agent):
    """Worry-Free Business Security does not send its policy to Vision One."""
    return "worry-free" in str(agent.get("protectionManager") or "").lower()


def transform(input):
    criteriaKey = "isEPPConfigured"
    try:
        endpoints, validation, failed = load_endpoints(criteriaKey, input, None)
        if failed:
            return failed
        no_agent = []
        no_policy = []
        unmeasured = []
        policies = {}
        for e in endpoints:
            if not has_protection_agent(e):
                no_agent.append(endpoint_name(e))
                continue
            agent = sub(e, "eppAgent")
            policy = agent.get("policyName")
            if isinstance(policy, str) and policy.strip():
                policies[policy.strip()] = policies.get(policy.strip(), 0) + 1
            elif policy_not_reported(agent):
                unmeasured.append(endpoint_name(e))
            else:
                no_policy.append(endpoint_name(e))
        measured = len(endpoints) - len(no_agent) - len(unmeasured)
        configured = measured - len(no_policy)
        protected = measured + len(unmeasured)
        if unmeasured and not no_policy:
            coverage = (measured * 100) // protected if protected else 0
            reason = ("%d of %d protection agents are managed by Worry-Free Business Security, which does not report its "
                      "policy to Vision One (%d%% measured), so configuration cannot be read here"
                      % (len(unmeasured), protected, coverage))
            return create_response(criteriaKey, {criteriaKey: None, "unmeasuredAgents": len(unmeasured),
                                                 "measuredAgents": measured, "measuredCoveragePercentage": coverage},
                                   validation=validation, api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Check the policy in the Worry-Free console, or attach evidence"])
        if protected == 0:
            if unmeasured:
                reason = ("%d protection agents are managed by Worry-Free Business Security, which does not report its "
                          "policy to Vision One, so configuration cannot be read here" % len(unmeasured))
            else:
                reason = "No endpoint has an installed protection agent, so there is no configuration to measure"
            return create_response(criteriaKey, {criteriaKey: None, "unmeasuredAgents": len(unmeasured)},
                                   validation=validation, api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Check the policy in the Worry-Free console, or attach evidence"] if unmeasured else None)
        value = (configured * 100) // protected
        summary = {"totalEndpoints": len(endpoints), "protectedEndpoints": protected,
                   "configuredEndpoints": configured, "endpointsWithoutPolicy": len(no_policy),
                   "endpointsWithoutProtectionAgent": len(no_agent), "policies": policies,
                   "sampleWithoutPolicy": no_policy[:10], "sampleWithoutProtectionAgent": no_agent[:10],
                   "unmeasuredAgents": len(unmeasured)}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if configured == protected:
            pass_reasons.append("All %d protection agents report an applied protection policy" % protected)
        else:
            if no_agent:
                fail_reasons.append("%d endpoints have no installed protection agent: %s" % (len(no_agent), ", ".join(no_agent[:10])))
            if no_policy:
                fail_reasons.append("%d protection agents report no applied policy: %s" % (len(no_policy), ", ".join(no_policy[:10])))
            if unmeasured:
                fail_reasons.append("%d Worry-Free managed agents do not report a policy to Vision One and are counted as not "
                                    "configured, so this is a lower bound" % len(unmeasured))
            recommendations.append("Assign a protection policy in the protection manager and confirm Vision One shows it on each endpoint")
        return create_response(criteriaKey, {criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary=summary)
    except Exception as e:
        return failure(criteriaKey, None, e)
