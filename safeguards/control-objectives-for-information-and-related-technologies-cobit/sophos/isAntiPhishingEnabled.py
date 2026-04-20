"""
Transformation: isAntiPhishingEnabled
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Confirm anti-phishing protection is enabled. Checks endpoint policies for a
threat-protection policy with web filtering, malicious URL detection, or phishing site blocking.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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


def evaluate(data):
    try:
        items = data.get("items", [])
        anti_phishing_keywords = ["phish", "web", "url", "maliciousUrl", "webFiltering", "webFilter", "webControl"]
        antiphishing_policy_found = False
        policy_name = ""
        for item in items:
            if item.get("type") != "threat-protection":
                continue
            if not item.get("enabled", False):
                continue
            settings = item.get("settings", {})
            settings_str = json.dumps(settings).lower()
            for kw in anti_phishing_keywords:
                if kw.lower() in settings_str:
                    antiphishing_policy_found = True
                    policy_name = item.get("name", "unnamed")
                    break
            if antiphishing_policy_found:
                break
        return {
            "isAntiPhishingEnabled": antiphishing_policy_found,
            "matchedPolicyName": policy_name,
            "totalPoliciesChecked": len(items)
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
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        if result_value:
            pass_reasons.append("Anti-phishing protection is enabled in a threat-protection policy")
            pass_reasons.append("matchedPolicyName: " + str(extra_fields.get("matchedPolicyName", "")))
        else:
            fail_reasons.append("No enabled threat-protection policy with anti-phishing or web filtering settings found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable web filtering and malicious URL detection in a Sophos threat-protection policy to block phishing sites")
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalPoliciesChecked": extra_fields.get("totalPoliciesChecked", 0), "matchedPolicyName": extra_fields.get("matchedPolicyName", "")})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
