"""
Transformation: isSafeLinksEnabled
Vendor: Proofpoint  |  Category: emailsecurity
Evaluates: Check if URL Defense (safe links rewriting and scanning) feature is enabled
for the organization in Proofpoint Essentials (getOrgFeatures).
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isSafeLinksEnabled",
                "vendor": "Proofpoint",
                "category": "emailsecurity"
            }
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"isSafeLinksEnabled": False, "error": "Unexpected data format"}

        features = data.get("features", {})
        if not isinstance(features, dict):
            features = {}

        url_defense = data.get("url_defense", features.get("url_defense", None))
        safe_links = data.get("safe_links", features.get("safe_links", None))
        url_rewriting = data.get("url_rewriting", features.get("url_rewriting", None))
        tap_url = data.get("tap_url_defense", features.get("tap_url_defense", None))

        is_enabled = (
            bool(url_defense) or
            bool(safe_links) or
            bool(url_rewriting) or
            bool(tap_url)
        )

        return {
            "isSafeLinksEnabled": is_enabled,
            "urlDefenseEnabled": url_defense,
            "safeLinksEnabled": safe_links,
            "urlRewritingEnabled": url_rewriting
        }
    except Exception as e:
        return {"isSafeLinksEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSafeLinksEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("URL Defense (safe links) is enabled in Proofpoint Essentials")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("URL Defense (safe links) is not enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Enable URL Defense in Proofpoint Essentials to protect users from malicious links"
            )
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        input_summary = {criteriaKey: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
