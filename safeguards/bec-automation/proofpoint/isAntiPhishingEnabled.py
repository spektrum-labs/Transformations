"""
Transformation: isAntiPhishingEnabled
Vendor: Proofpoint  |  Category: bec-automation
Evaluates: Whether anti-phishing and anti-spoofing protections are active in org features
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Proofpoint", "category": "bec-automation"}
        }
    }


def check_feature_value(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ["true", "enabled", "active", "1"]
    if isinstance(val, int):
        return val == 1
    return False


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"isAntiPhishingEnabled": False, "error": "Unexpected data format: expected dict"}

        antiphish_keys = [
            "anti_spoofing", "antiSpoofing", "impersonation_protection", "impersonationProtection",
            "anti_phishing", "antiPhishing", "phishing_protection", "phishingProtection",
            "bec_detection", "becDetection", "spoof_protection", "spoofProtection"
        ]

        findings = []
        enabled_features = []

        features_src = data
        nested_features = data.get("features", {})
        if isinstance(nested_features, dict) and len(nested_features) > 0:
            features_src = nested_features

        for key in antiphish_keys:
            val = features_src.get(key, None)
            if val is not None:
                is_on = check_feature_value(val)
                if is_on:
                    enabled_features.append(key)
                findings.append(key + "=" + str(val))

        is_enabled = len(enabled_features) > 0

        return {
            "isAntiPhishingEnabled": is_enabled,
            "enabledFeatures": ", ".join(enabled_features) if enabled_features else "none",
            "featuresChecked": ", ".join(findings) if findings else "none_found"
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
            return create_response(
                result={criteriaKey: False}, validation=validation,
                fail_reasons=["Input validation failed"])
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
            pass_reasons.append(criteriaKey + " check passed")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable anti-spoofing and impersonation protection features in Proofpoint Essentials to defend against phishing and BEC attacks.")
        result = {criteriaKey: result_value}
        for k in extra_fields:
            result[k] = extra_fields[k]
        input_summary = {criteriaKey: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]
        return create_response(
            result=result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations, input_summary=input_summary)
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
