"""
Transformation: isEPPEnabled
Vendor: Crowdstrike  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Whether at least one CrowdStrike prevention policy has enabled: true,
           confirming EPP/NGAV prevention is actively enforced in the environment.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Crowdstrike", "category": "cloud-security-alliance-star-csa-star"}
        }
    }


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not resources:
            return {"isEPPEnabled": False, "totalPreventionPolicies": 0, "enabledPreventionPolicies": 0, "error": "No policy resources found in API response"}

        # Prevention policies are distinguished from sensor-update policies by having prevention_settings
        prevention_policies = [r for r in resources if "prevention_settings" in r]
        total_count = len(prevention_policies)

        if total_count == 0:
            return {"isEPPEnabled": False, "totalPreventionPolicies": 0, "enabledPreventionPolicies": 0, "error": "No prevention policies found in merged policy data"}

        enabled_policies = [p for p in prevention_policies if p.get("enabled", False)]
        enabled_count = len(enabled_policies)
        enabled_names = [p.get("name", "unnamed") for p in enabled_policies]

        is_enabled = enabled_count > 0
        return {
            "isEPPEnabled": is_enabled,
            "totalPreventionPolicies": total_count,
            "enabledPreventionPolicies": enabled_count,
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

        total = eval_result.get("totalPreventionPolicies", 0)
        enabled = eval_result.get("enabledPreventionPolicies", 0)
        names = eval_result.get("enabledPolicyNames", [])

        if result_value:
            pass_reasons.append("At least one CrowdStrike prevention policy is actively enabled")
            pass_reasons.append("Enabled prevention policies: " + str(enabled) + " of " + str(total))
            if names:
                additional_findings.append("Enabled policy names: " + ", ".join(names))
        else:
            fail_reasons.append("No enabled CrowdStrike prevention policies found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable at least one prevention policy in the CrowdStrike Falcon console to enforce EPP/NGAV protection")
            recommendations.append("Navigate to Endpoint Security > Prevention Policies and ensure policies are enabled and assigned to host groups")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPreventionPolicies": total, "enabledPreventionPolicies": enabled}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
