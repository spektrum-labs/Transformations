"""
Transformation: isConditionalAccessEnabled
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management
API: GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies  (Policy.Read.All)
Docs: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies
      https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy

Question (CMMC AC.L2-3.1.12): do Conditional Access policies monitor and control access sessions?

A policy counts only when it is ENFORCED and actually controls something:
  * state == "enabled". "enabledForReportingButNotEnforced" (report-only) and "disabled" never count:
    Microsoft documents report-only as evaluating without enforcing.
  * it grants or blocks (grantControls.builtInControls non-empty, or an authenticationStrength object),
    or it sets at least one session control (sessionControls.<control>.isEnabled == true, or
    applicationEnforcedRestrictions / cloudAppSecurity enabled).

Output (numbers first):
  enforcedPolicyCount, reportOnlyPolicyCount, disabledPolicyCount, policyCount
  isConditionalAccessEnabled = enforcedPolicyCount >= 1

Fails closed (None with dataCollection.status "error"): no policy list in the body, an error body, a body
that is not a Graph collection, or a partial page (@odata.nextLink present) on which no enforced policy
was found. An empty but complete list is a measurement: zero policies -> False.
"""
import json
from datetime import datetime

KEY = "isConditionalAccessEnabled"
WRAPPERS = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse", "data"]


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "azure_isconditionalaccessenabled",
                         "vendor": "Microsoft Entra ID", "category": "Identity and Access Management"},
        },
    }


def not_measured(reason, validation=None):
    return create_response(
        result={KEY: None, "enforcedPolicyCount": None},
        validation=validation,
        api_errors=[reason],
        fail_reasons=[reason],
    )


def unwrap(data):
    for attempt in range(6):
        if isinstance(data, (str, bytes)):
            try:
                data = json.loads(data)
            except ValueError:
                return None
        if not isinstance(data, dict) or "value" in data or "conditionalAccessPolicies" in data:
            return data
        moved = False
        for key in WRAPPERS:
            if key in data and isinstance(data.get(key), (dict, list)):
                data = data[key]
                moved = True
                break
        if not moved:
            return data
    return data


def policy_collection(data):
    """-> (policies, partial) or (None, False) when the body is not a CA policy collection."""
    data = unwrap(data)
    if isinstance(data, dict) and isinstance(data.get("conditionalAccessPolicies"), dict):
        data = data["conditionalAccessPolicies"]
    if not isinstance(data, dict):
        return None, False
    if data.get("error") or data.get("errors"):
        return None, False
    policies = data.get("value")
    if not isinstance(policies, list):
        return None, False
    context = str(data.get("@odata.context") or "")
    if policies == [] and "conditionalAccess" not in context:
        # An empty list with no Graph context could be anything; it proves nothing.
        return None, False
    partial = bool(data.get("@odata.nextLink"))
    return [p for p in policies if isinstance(p, dict)], partial


def is_on(control):
    return isinstance(control, dict) and control.get("isEnabled") is True


def controls_something(policy):
    grant = policy.get("grantControls")
    if isinstance(grant, dict):
        built_in = grant.get("builtInControls")
        if isinstance(built_in, list) and len([c for c in built_in if isinstance(c, str) and c]) > 0:
            return True
        strength = grant.get("authenticationStrength")
        if isinstance(strength, dict) and strength.get("id"):
            return True
    session = policy.get("sessionControls")
    if isinstance(session, dict):
        for name in ["signInFrequency", "persistentBrowser", "applicationEnforcedRestrictions", "cloudAppSecurity",
                     "continuousAccessEvaluation", "secureSignInSession"]:
            control = session.get(name)
            if is_on(control):
                return True
            if name == "continuousAccessEvaluation" and isinstance(control, dict) and control.get("mode") == "strictEnforcement":
                return True
    return False


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        validation = {"status": "unknown", "errors": [], "warnings": []}
        data = input
        if isinstance(input, dict) and "data" in input and "validation" in input:
            data = input.get("data")
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
        policies, partial = policy_collection(data)
        if policies is None:
            return not_measured("No Conditional Access policy list was returned (error or unrecognised body)", validation)
        enforced = []
        report_only = 0
        disabled = 0
        for policy in policies:
            state = str(policy.get("state") or "").strip()
            if state == "enabled":
                if controls_something(policy):
                    enforced.append(str(policy.get("displayName") or policy.get("id") or "unnamed"))
            elif state == "enabledForReportingButNotEnforced":
                report_only = report_only + 1
            elif state == "disabled":
                disabled = disabled + 1
        count = len(enforced)
        if count == 0 and partial:
            return not_measured("Only a partial page of Conditional Access policies was returned and none is enforced on it",
                                validation)
        result = {
            KEY: count >= 1,
            "enforcedPolicyCount": count,
            "reportOnlyPolicyCount": report_only,
            "disabledPolicyCount": disabled,
            "policyCount": len(policies),
        }
        summary = {"policyCount": len(policies), "partialPage": partial}
        if count >= 1:
            return create_response(result, validation,
                                   pass_reasons=[str(count) + " enforced Conditional Access polic" + ("y" if count == 1 else "ies")
                                                 + " control sign-in or session: " + ", ".join(enforced[:10])],
                                   input_summary=summary)
        reason = "No Conditional Access policy is enforced (" + str(report_only) + " report-only, " + str(disabled) + " disabled)"
        return create_response(result, validation, fail_reasons=[reason],
                               recommendations=["Switch the Conditional Access policies from report-only to On"],
                               input_summary=summary)
    except Exception as e:
        return not_measured("Transformation error: " + str(e))
