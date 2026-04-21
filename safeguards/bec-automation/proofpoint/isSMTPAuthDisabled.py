"""
Transformation: isSMTPAuthDisabled
Vendor: Proofpoint  |  Category: bec-automation
Evaluates: Whether SMTP AUTH is disabled or restricted at the organizational level in org details
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSMTPAuthDisabled", "vendor": "Proofpoint", "category": "bec-automation"}
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
            return {"isSMTPAuthDisabled": False, "error": "Unexpected data format: expected dict"}

        smtp_auth_enabled_keys = [
            "smtp_auth_enabled", "smtpAuthEnabled", "smtp_auth", "smtpAuth",
            "smtp_authentication", "smtpAuthentication", "allow_smtp_auth", "allowSmtpAuth"
        ]

        detected_key = "none"
        detected_value = None
        found = False

        for key in smtp_auth_enabled_keys:
            if key in data:
                detected_key = key
                detected_value = data[key]
                found = True
                break

        if not found:
            smtp_disabled_keys = [
                "smtp_auth_disabled", "smtpAuthDisabled", "disable_smtp_auth", "disableSmtpAuth"
            ]
            for key in smtp_disabled_keys:
                if key in data:
                    detected_key = key
                    detected_value = data[key]
                    is_disabled = check_feature_value(detected_value)
                    return {
                        "isSMTPAuthDisabled": is_disabled,
                        "detectedField": detected_key,
                        "detectedValue": str(detected_value)
                    }

        if not found:
            return {
                "isSMTPAuthDisabled": False,
                "detectedField": "none",
                "detectedValue": "not_found",
                "note": "No SMTP auth field detected; assuming enabled (not disabled)"
            }

        smtp_auth_is_enabled = check_feature_value(detected_value)
        is_disabled = not smtp_auth_is_enabled

        return {
            "isSMTPAuthDisabled": is_disabled,
            "detectedField": detected_key,
            "detectedValue": str(detected_value)
        }
    except Exception as e:
        return {"isSMTPAuthDisabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSMTPAuthDisabled"
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
            recommendations.append("Disable SMTP AUTH at the organizational level in Proofpoint Essentials to reduce the risk of credential-based email abuse.")
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
