"""
Transformation: isEPPConfigured
Vendor: Crowdstrike  |  Category: epp
Evaluates: Whether at least one prevention policy has a non-empty prevention_settings
           array with configured blocking or detection categories set to a non-disabled value.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Crowdstrike", "category": "epp"}
        }
    }


def get_prevention_policies(data):
    """Extract prevention policies list from merged or direct API response."""
    if isinstance(data, dict):
        method_data = data.get("getPreventionPolicies", None)
        if method_data is not None:
            if isinstance(method_data, dict):
                return method_data.get("data", [])
            if isinstance(method_data, list):
                return method_data
        direct = data.get("data", None)
        if isinstance(direct, list):
            return direct
        resources = data.get("resources", None)
        if isinstance(resources, list):
            return resources
    if isinstance(data, list):
        return data
    return []


def is_setting_active(setting):
    """Return True if a prevention setting is set to a non-disabled/non-cautious value."""
    value = setting.get("value", None)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        if "enabled" in value:
            return value.get("enabled", False) is True
        disabled_values = ["DISABLED", "CAUTIOUS", "NO_POLICY", ""]
        detection = value.get("detection", "DISABLED")
        prevention = value.get("prevention", "DISABLED")
        if detection not in disabled_values or prevention not in disabled_values:
            return True
    return False


def policy_has_active_settings(policy):
    """Return True if a policy has at least one active prevention setting group."""
    prevention_settings = policy.get("prevention_settings", [])
    if not prevention_settings:
        return False
    for group in prevention_settings:
        settings = group.get("settings", [])
        for setting in settings:
            if is_setting_active(setting):
                return True
    return False


def evaluate(data):
    """Check if at least one prevention policy has active, configured settings."""
    try:
        policies = get_prevention_policies(data)
        total_policies = len(policies)
        configured_policies = [p for p in policies if policy_has_active_settings(p)]
        configured_count = len(configured_policies)
        configured_names = [p.get("name", "unnamed") for p in configured_policies]
        is_configured = configured_count > 0
        return {
            "isEPPConfigured": is_configured,
            "totalPolicies": total_policies,
            "configuredPoliciesCount": configured_count,
            "configuredPolicyNames": configured_names
        }
    except Exception as e:
        return {"isEPPConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPConfigured"
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
        additional_findings = []
        if result_value:
            pass_reasons.append("At least one prevention policy has active blocking or detection settings configured.")
            pass_reasons.append("Configured policies: " + str(eval_result.get("configuredPoliciesCount", 0)) + " of " + str(eval_result.get("totalPolicies", 0)))
        else:
            fail_reasons.append("No prevention policies with active blocking or detection settings were found.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure malware, ransomware, or exploit prevention settings in at least one active Falcon prevention policy.")
        if eval_result.get("totalPolicies", 0) == 0:
            additional_findings.append("No prevention policies returned — verify API scope includes Prevention Policies Read.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPolicies": eval_result.get("totalPolicies", 0), "configuredPoliciesCount": eval_result.get("configuredPoliciesCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
