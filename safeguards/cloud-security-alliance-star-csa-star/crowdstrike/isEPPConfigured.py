"""
Transformation: isEPPConfigured
Vendor: Crowdstrike  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Whether at least one enabled prevention policy contains a non-empty
           prevention_settings object with configured detection and prevention
           categories, confirming EPP is configured per vendor guidance.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Crowdstrike", "category": "cloud-security-alliance-star-csa-star"}
        }
    }


def has_configured_settings(prevention_settings):
    if not prevention_settings:
        return False
    categories = prevention_settings.get("categories", [])
    if categories and len(categories) > 0:
        return True
    # Also accept if settings has any non-empty top-level keys besides categories
    for key in prevention_settings:
        val = prevention_settings[key]
        if val and key != "categories":
            return True
    return False


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not resources:
            return {"isEPPConfigured": False, "totalPreventionPolicies": 0, "configuredPolicies": 0, "error": "No policy resources found in API response"}

        prevention_policies = [r for r in resources if "prevention_settings" in r]
        total_count = len(prevention_policies)

        if total_count == 0:
            return {"isEPPConfigured": False, "totalPreventionPolicies": 0, "configuredPolicies": 0, "error": "No prevention policies found in merged policy data"}

        configured_names = []
        unconfigured_names = []
        for p in prevention_policies:
            if not p.get("enabled", False):
                continue
            settings = p.get("prevention_settings", {})
            if has_configured_settings(settings):
                configured_names.append(p.get("name", "unnamed"))
            else:
                unconfigured_names.append(p.get("name", "unnamed"))

        configured_count = len(configured_names)
        is_configured = configured_count > 0

        return {
            "isEPPConfigured": is_configured,
            "totalPreventionPolicies": total_count,
            "configuredPolicies": configured_count,
            "configuredPolicyNames": configured_names,
            "unconfiguredEnabledPolicyNames": unconfigured_names
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

        total = eval_result.get("totalPreventionPolicies", 0)
        configured = eval_result.get("configuredPolicies", 0)
        configured_names = eval_result.get("configuredPolicyNames", [])
        unconfigured_names = eval_result.get("unconfiguredEnabledPolicyNames", [])

        if result_value:
            pass_reasons.append("At least one enabled prevention policy has configured prevention_settings categories")
            pass_reasons.append("Configured policies: " + str(configured) + " of " + str(total) + " total prevention policies")
            if configured_names:
                additional_findings.append("Configured policy names: " + ", ".join(configured_names))
        else:
            fail_reasons.append("No enabled prevention policy with configured prevention_settings categories found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure prevention settings categories in at least one enabled prevention policy")
            recommendations.append("In the Falcon console, navigate to Endpoint Security > Prevention Policies and configure detection/prevention categories")
            if unconfigured_names:
                additional_findings.append("Enabled policies with empty or missing settings: " + ", ".join(unconfigured_names))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPreventionPolicies": total, "configuredPolicies": configured}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
