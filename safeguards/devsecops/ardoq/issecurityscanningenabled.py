"""
Transformation: isSecurityScanningEnabled
Vendor: Ardoq
Category: DevSecOps

Evaluates isSecurityScanningEnabled for Ardoq
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSecurityScanningEnabled", "vendor": "Ardoq", "category": "DevSecOps"}
        }
    }


def transform(input):
    criteriaKey = "isSecurityScanningEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        components = data.get("values", data.get("data", data.get("components", data.get("items", []))))

        if not isinstance(components, list):
            total_count = data.get("totalCount", data.get("total", data.get("count", 0)))
            if isinstance(total_count, int) and total_count > 0:
                return create_response(
                    result={
                    "isSecurityScanningEnabled": True,
                    "activeComponents": total_count,
                    "totalComponents": total_count
                },
                    validation=validation
                )
            return create_response(
                result={
                "isSecurityScanningEnabled": False,
                "activeComponents": 0,
                "totalComponents": 0,
                "error": "Unexpected response format"
            },
                validation=validation,
                fail_reasons=["isSecurityScanningEnabled check failed"]
            )
        total = len(components)
        result = total > 0
        # -- END EVALUATION LOGIC --

        return create_response(

            result={
            "isSecurityScanningEnabled": result,
            "activeComponents": total,
            "totalComponents": total
        },

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
