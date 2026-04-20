"""
Transformation: isEPPLoggingEnabled
Vendor: Crowdstrike  |  Category: epp
Evaluates: Whether prevention policies include detection or monitoring settings with
           detect or block mode enabled, confirming event telemetry and audit logging
           is active for endpoint activity.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Crowdstrike", "category": "epp"}
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


def setting_has_detection(setting):
    """
    Return True if a setting has an active detection mode (not DISABLED).
    Covers toggle-style ({"enabled": true}) and mlslider-style ({"detection": "MODERATE", ...}).
    """
    value = setting.get("value", None)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        if "enabled" in value:
            return value.get("enabled", False) is True
        detection = value.get("detection", "DISABLED")
        disabled_vals = ["DISABLED", "NO_POLICY", ""]
        if detection not in disabled_vals:
            return True
    return False


def policy_has_detection_settings(policy):
    """Return True if an enabled policy has at least one setting with active detection mode."""
    if not policy.get("enabled", False):
        return False
    prevention_settings = policy.get("prevention_settings", [])
    for group in prevention_settings:
        settings = group.get("settings", [])
        for setting in settings:
            if setting_has_detection(setting):
                return True
    return False


def evaluate(data):
    """Check if detection/logging settings are active in at least one enabled policy."""
    try:
        policies = get_prevention_policies(data)
        total_policies = len(policies)
        enabled_policies = [p for p in policies if p.get("enabled", False) is True]
        enabled_count = len(enabled_policies)
        logging_policies = [p for p in policies if policy_has_detection_settings(p)]
        logging_count = len(logging_policies)
        logging_names = [p.get("name", "unnamed") for p in logging_policies]
        is_logging_enabled = logging_count > 0
        return {
            "isEPPLoggingEnabled": is_logging_enabled,
            "totalPolicies": total_policies,
            "enabledPoliciesCount": enabled_count,
            "policiesWithDetectionCount": logging_count,
            "policiesWithDetectionNames": logging_names
        }
    except Exception as e:
        return {"isEPPLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPLoggingEnabled"
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
            pass_reasons.append("At least one enabled prevention policy has active detection mode settings, confirming event telemetry and audit logging is active.")
            pass_reasons.append("Policies with detection enabled: " + str(eval_result.get("policiesWithDetectionCount", 0)) + " of " + str(eval_result.get("enabledPoliciesCount", 0)) + " enabled policies.")
        else:
            fail_reasons.append("No enabled prevention policies with active detection mode settings were found.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if eval_result.get("enabledPoliciesCount", 0) == 0:
                recommendations.append("Enable at least one prevention policy and configure detection settings to activate endpoint event logging.")
            else:
                recommendations.append("Review prevention policy detection settings — set detection mode to MODERATE or AGGRESSIVE for malware and exploit categories.")
        if eval_result.get("totalPolicies", 0) == 0:
            additional_findings.append("No prevention policies returned — verify API scope includes Prevention Policies Read.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPolicies": eval_result.get("totalPolicies", 0), "enabledPoliciesCount": eval_result.get("enabledPoliciesCount", 0), "policiesWithDetectionCount": eval_result.get("policiesWithDetectionCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
