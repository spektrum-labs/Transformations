"""
Transformation: isAntiPhishingEnabled
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether anti-phishing controls are enabled in Sophos Email Security policies by
checking for phishing detection, impersonation protection, and suspicious URL scanning settings.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def policy_has_antiphishing(policy):
    settings = policy.get("settings", {})
    if not settings:
        return False
    phishing = settings.get("phishing", {})
    if phishing and phishing.get("enabled", False):
        return True
    anti_phishing = settings.get("antiPhishing", {})
    if anti_phishing and anti_phishing.get("enabled", False):
        return True
    impersonation = settings.get("impersonationProtection", {})
    if impersonation and impersonation.get("enabled", False):
        return True
    url_scanning = settings.get("suspiciousUrls", {})
    if url_scanning and url_scanning.get("enabled", False):
        return True
    url_click = settings.get("urlClickTimeProtection", {})
    if url_click and url_click.get("enabled", False):
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {
                "isAntiPhishingEnabled": False,
                "error": "No email policy items found in response",
                "totalPolicies": 0,
                "antiPhishingEnabledCount": 0
            }

        total = len(items)
        enabled_count = 0
        for policy in items:
            if policy_has_antiphishing(policy):
                enabled_count = enabled_count + 1

        is_enabled = enabled_count > 0

        return {
            "isAntiPhishingEnabled": is_enabled,
            "totalPolicies": total,
            "antiPhishingEnabledCount": enabled_count
        }
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isAntiPhishingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteria_key: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteria_key and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Anti-phishing controls are enabled in at least one Sophos Email policy")
            pass_reasons.append(str(extra_fields.get("antiPhishingEnabledCount", 0)) + " of " + str(extra_fields.get("totalPolicies", 0)) + " policies have anti-phishing configured")
        else:
            fail_reasons.append("No Sophos Email policies have anti-phishing controls enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable phishing detection and impersonation protection in Sophos Email Security policies")
            recommendations.append("Configure suspicious URL scanning in Sophos Email policies")
        combined = {criteria_key: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteria_key: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0)})
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
