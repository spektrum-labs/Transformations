"""
Transformation: compliance
Vendor: Compliance Management
Category: Compliance

Calculates the compliance level based on the input data.
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
                "transformationId": "compliance",
                "vendor": "Compliance Management",
                "category": "Compliance"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"complianceLevel": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        compliance_level = 0
        if isinstance(data, dict):
            compliance_level = data.get("complianceLevel", 0)

        if compliance_level >= 80:
            pass_reasons.append(f"Compliance level is good: {compliance_level}%")
        elif compliance_level >= 50:
            fail_reasons.append(f"Compliance level is moderate: {compliance_level}%")
            recommendations.append("Improve compliance by addressing identified gaps")
        else:
            fail_reasons.append(f"Compliance level is low: {compliance_level}%")
            recommendations.append("Urgently address compliance gaps to meet requirements")

        return create_response(
            result={"complianceLevel": compliance_level},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"complianceLevel": compliance_level}
        )

    except Exception as e:
        return create_response(
            result={"complianceLevel": 0},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
