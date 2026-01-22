"""
Transformation: isBehavioralMonitoringValid
Vendor: Endpoint Protection Platform
Category: Endpoint Security

Evaluates if behavioral monitoring is valid and functioning.
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBehavioralMonitoringValid",
                "vendor": "Endpoint Protection Platform",
                "category": "Endpoint Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isBehavioralMonitoringValid"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Default to True if data is present (indicates active integration)
        default_value = data is not None

        is_behavioral_monitoring_valid = False
        if isinstance(data, dict):
            is_behavioral_monitoring_valid = data.get('isBehavioralMonitoringValid', default_value)
        else:
            is_behavioral_monitoring_valid = default_value

        if is_behavioral_monitoring_valid:
            pass_reasons.append("Behavioral monitoring is valid and functioning")
        else:
            fail_reasons.append("Behavioral monitoring is not valid or not functioning")
            recommendations.append("Enable and verify behavioral monitoring configuration")

        return create_response(
            result={criteriaKey: is_behavioral_monitoring_valid},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"behavioralMonitoringValid": is_behavioral_monitoring_valid}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
