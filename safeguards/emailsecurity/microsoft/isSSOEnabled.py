"""
Transformation: isSSOEnabled
Vendor: Microsoft  |  Category: emailsecurity
Evaluates: Inspects Conditional Access Policies for enabled policies with session controls (persistent browser or sign-in frequency), indicating SSO is actively managed.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "Microsoft", "category": "emailsecurity"}
        }
    }


def has_sso_session_controls(policy):
    if policy.get("state", "") != "enabled":
        return False
    session_controls = policy.get("sessionControls", None)
    if session_controls is None:
        return False
    persistent_browser = session_controls.get("persistentBrowser", None)
    sign_in_frequency = session_controls.get("signInFrequency", None)
    if persistent_browser is not None and persistent_browser.get("isEnabled", False):
        return True
    if sign_in_frequency is not None and sign_in_frequency.get("isEnabled", False):
        return True
    return False


def evaluate(data):
    try:
        policies = data.get("value", [])
        if not policies:
            nested = data.get("getConditionalAccessPolicies", {})
            if isinstance(nested, dict):
                policies = nested.get("value", [])
        if not isinstance(policies, list):
            policies = []
        total_policies = len(policies)
        enabled_policies = [p for p in policies if p.get("state", "") == "enabled"]
        sso_policies = [p for p in enabled_policies if has_sso_session_controls(p)]
        sso_policy_names = [p.get("displayName", "Unnamed") for p in sso_policies]
        is_sso_enabled = len(sso_policies) > 0
        return {
            "isSSOEnabled": is_sso_enabled,
            "totalPolicies": total_policies,
            "enabledPoliciesCount": len(enabled_policies),
            "ssoPoliciesCount": len(sso_policies),
            "ssoPolicyNames": ", ".join(sso_policy_names) if sso_policy_names else "None"
        }
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSSOEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Enabled Conditional Access policy with SSO session controls found")
            pass_reasons.append("SSO-managing policies: " + eval_result.get("ssoPolicyNames", "None"))
        else:
            fail_reasons.append("No enabled Conditional Access policy with persistent browser or sign-in frequency session controls found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create a Conditional Access policy with session controls (persistent browser or sign-in frequency) in Microsoft Entra ID to manage SSO behavior")
        merged_result = {criteriaKey: result_value}
        for k in extra_fields:
            merged_result[k] = extra_fields[k]
        return create_response(
            result=merged_result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={"totalPolicies": eval_result.get("totalPolicies", 0), "ssoPoliciesCount": eval_result.get("ssoPoliciesCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
