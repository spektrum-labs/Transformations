"""
Transformation: isEPPLoggingEnabled
Vendor: Halcyon  |  Category: epp
Evaluates: Checks whether EPP event logging is enabled for audit, monitoring, and compliance purposes.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Halcyon", "category": "epp"}
        }
    }


def extract_bool_flag(data, primary_keys, fallback_status_values):
    """
    Attempts to read a boolean flag from a dict.
    Tries primary_keys first (exact bool/int), then looks for a 'status' string
    matched against fallback_status_values.
    Returns (found: bool, value: bool).
    """
    for key in primary_keys:
        if key in data:
            raw = data[key]
            if isinstance(raw, bool):
                return True, raw
            if isinstance(raw, int):
                return True, raw != 0
            if isinstance(raw, str):
                return True, raw.lower() in fallback_status_values
    status_val = data.get("status", "")
    if isinstance(status_val, str) and status_val != "":
        return True, status_val.lower() in fallback_status_values
    return False, False


def evaluate(data):
    """
    Determines whether EPP logging is enabled.
    Accepts several common field shapes returned by the Halcyon API.
    """
    try:
        positive_strings = ["enabled", "true", "active", "on", "yes", "1"]

        inner = data
        if isinstance(data.get("data"), dict):
            inner = data["data"]

        primary_keys = [
            "isEPPLoggingEnabled",
            "loggingEnabled",
            "logging_enabled",
            "enabled",
            "result",
            "passed",
            "pass",
            "value",
        ]

        found, flag_value = extract_bool_flag(inner, primary_keys, positive_strings)

        if not found:
            found, flag_value = extract_bool_flag(data, primary_keys, positive_strings)

        if not found:
            return {
                "isEPPLoggingEnabled": False,
                "error": "Could not determine EPP logging status from API response",
            }

        return {"isEPPLoggingEnabled": flag_value}
    except Exception as e:
        return {"isEPPLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPLoggingEnabled"
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
                fail_reasons=["Input validation failed"],
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("EPP event logging is enabled -- audit and compliance requirements are met.")
        else:
            fail_reasons.append("EPP event logging is not enabled.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Enable EPP logging in the Halcyon console to ensure endpoint events are "
                "captured for audit, monitoring, and compliance purposes."
            )
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value},
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)],
        )
