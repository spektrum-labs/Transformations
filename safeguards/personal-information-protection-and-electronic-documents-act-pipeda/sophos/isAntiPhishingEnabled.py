"""
Transformation: isAntiPhishingEnabled
Vendor: Sophos  |  Category: personal-information-protection-and-electronic-documents-act-pipeda
Evaluates: Whether phishing detection and impersonation protection settings are enabled in Sophos Email base or custom policies.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Sophos", "category": "personal-information-protection-and-electronic-documents-act-pipeda"}
        }
    }


def find_antiphishing_in_policy(policy):
    settings = policy.get("settings", {})

    phishing = settings.get("phishing", {})
    phishing_enabled = phishing.get("enabled", False) or phishing.get("detection", False)

    impersonation = settings.get("impersonation", {})
    impersonation_enabled = impersonation.get("enabled", False)

    anti_phishing = settings.get("antiPhishing", {})
    anti_phishing_enabled = anti_phishing.get("enabled", False)

    inbound = settings.get("inbound", {})
    inbound_phishing = inbound.get("phishing", {})
    inbound_enabled = inbound_phishing.get("enabled", False) or inbound_phishing.get("detection", False)

    inbound_impersonation = inbound.get("impersonation", {})
    inbound_impersonation_enabled = inbound_impersonation.get("enabled", False)

    url_protection = settings.get("urlProtection", {})
    malicious_url = url_protection.get("maliciousUrlDetection", False) or url_protection.get("enabled", False)

    return (phishing_enabled or impersonation_enabled or anti_phishing_enabled or
            inbound_enabled or inbound_impersonation_enabled or malicious_url)


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"isAntiPhishingEnabled": False, "error": "No email policy items found in response"}

        base_policy_antiphishing = False
        custom_policy_antiphishing = False
        policies_checked = 0
        phishing_policy_names = []

        for policy in items:
            policy_type = policy.get("type", "").lower()
            is_base = policy_type in ["base", "default"] or policy.get("isDefault", False) or policy.get("name", "").lower() in ["base policy", "default"]

            found = find_antiphishing_in_policy(policy)
            policies_checked = policies_checked + 1

            if found:
                phishing_policy_names.append(policy.get("name", "unnamed"))

            if is_base and found:
                base_policy_antiphishing = True
            if not is_base and found:
                custom_policy_antiphishing = True

        antiphishing_enabled = base_policy_antiphishing or custom_policy_antiphishing

        return {
            "isAntiPhishingEnabled": antiphishing_enabled,
            "basePolicyAntiPhishingEnabled": base_policy_antiphishing,
            "customPolicyAntiPhishingEnabled": custom_policy_antiphishing,
            "totalPoliciesChecked": policies_checked,
            "enabledInPolicies": phishing_policy_names
        }
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"
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
        enabled_in = extra_fields.get("enabledInPolicies", [])
        if result_value:
            pass_reasons.append("Anti-phishing and impersonation protection is enabled in Sophos Email policies")
            if extra_fields.get("basePolicyAntiPhishingEnabled", False):
                pass_reasons.append("Anti-phishing is configured in the base/default policy")
            if extra_fields.get("customPolicyAntiPhishingEnabled", False):
                pass_reasons.append("Anti-phishing is configured in one or more custom policies")
            if enabled_in:
                pass_reasons.append("Policies with anti-phishing enabled: " + ", ".join(enabled_in))
        else:
            fail_reasons.append("Anti-phishing protection is not enabled in any Sophos Email policy")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable phishing detection in the Sophos Email base policy inbound settings")
            recommendations.append("Enable impersonation protection to guard against executive impersonation attacks")
            recommendations.append("Consider enabling URL protection with malicious URL detection for additional coverage")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
