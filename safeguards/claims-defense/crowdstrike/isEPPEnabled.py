"""
Transformation: isEPPEnabled
Vendor: Crowdstrike  |  Category: claims-defense
Evaluates: Check that at least one Prevention Policy resource has 'enabled: true', confirming
that endpoint protection (NGAV/EPP) is actively enforced across the environment.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Crowdstrike", "category": "claims-defense"}
        }
    }


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not isinstance(resources, list):
            resources = []
        total_policies = len(resources)
        enabled_policies = []
        disabled_policies = []
        for policy in resources:
            if not isinstance(policy, dict):
                continue
            policy_name = policy.get("name", "Unknown")
            policy_id = policy.get("id", "")
            if policy.get("enabled", False):
                enabled_policies.append(policy_name + " (" + policy_id + ")")
            else:
                disabled_policies.append(policy_name + " (" + policy_id + ")")
        enabled_count = len(enabled_policies)
        is_epp_enabled = enabled_count > 0
        return {
            "isEPPEnabled": is_epp_enabled,
            "totalPolicies": total_policies,
            "enabledPoliciesCount": enabled_count,
            "disabledPoliciesCount": len(disabled_policies),
            "enabledPolicies": enabled_policies,
            "disabledPolicies": disabled_policies
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
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {}
        extra_fields["totalPolicies"] = eval_result.get("totalPolicies", 0)
        extra_fields["enabledPoliciesCount"] = eval_result.get("enabledPoliciesCount", 0)
        extra_fields["disabledPoliciesCount"] = eval_result.get("disabledPoliciesCount", 0)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("At least one CrowdStrike Prevention Policy is enabled, confirming EPP is actively enforced.")
            pass_reasons.append("Enabled prevention policies: " + str(eval_result.get("enabledPoliciesCount", 0)) + " of " + str(eval_result.get("totalPolicies", 0)))
            enabled_list = eval_result.get("enabledPolicies", [])
            if enabled_list:
                additional_findings.append("Enabled policies: " + ", ".join(enabled_list))
        else:
            fail_reasons.append("No CrowdStrike Prevention Policies are in an enabled state.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable at least one Prevention Policy in the CrowdStrike Falcon console to enforce endpoint protection.")
            recommendations.append("Navigate to Endpoint Security > Prevention Policies and toggle policies to Enabled.")
        disabled_list = eval_result.get("disabledPolicies", [])
        if disabled_list:
            additional_findings.append("Disabled policies: " + ", ".join(disabled_list))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
