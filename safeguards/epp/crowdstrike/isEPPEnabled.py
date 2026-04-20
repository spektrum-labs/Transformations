"""
Transformation: isEPPEnabled
Vendor: Crowdstrike  |  Category: epp
Evaluates: Whether at least one CrowdStrike prevention policy has enabled=true,
           confirming the EPP/NGAV agent protection is actively enforced.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Crowdstrike", "category": "epp"}
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


def evaluate(data):
    """Check if at least one prevention policy is enabled."""
    try:
        policies = get_prevention_policies(data)
        total_policies = len(policies)
        enabled_policies = [p for p in policies if p.get("enabled", False) is True]
        enabled_count = len(enabled_policies)
        enabled_names = [p.get("name", "unnamed") for p in enabled_policies]
        is_enabled = enabled_count > 0
        return {
            "isEPPEnabled": is_enabled,
            "totalPolicies": total_policies,
            "enabledPoliciesCount": enabled_count,
            "enabledPolicyNames": enabled_names
        }
    except Exception as e:
        return {"isEPPEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPEnabled"
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
            pass_reasons.append("At least one CrowdStrike prevention policy is enabled.")
            pass_reasons.append("Enabled policies: " + str(eval_result.get("enabledPoliciesCount", 0)) + " of " + str(eval_result.get("totalPolicies", 0)))
        else:
            fail_reasons.append("No enabled CrowdStrike prevention policies found.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable at least one prevention policy in the CrowdStrike Falcon Console to activate EPP protection.")
        if eval_result.get("totalPolicies", 0) == 0:
            additional_findings.append("No prevention policies were returned by the API — verify API permissions include Prevention Policies Read scope.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPolicies": eval_result.get("totalPolicies", 0), "enabledPoliciesCount": eval_result.get("enabledPoliciesCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
