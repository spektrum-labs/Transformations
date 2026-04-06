"""
Transformation: isComplianceMonitored
Vendor: Anvilogic
Category: GRC

Evaluates isComplianceMonitored for Anvilogic
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isComplianceMonitored", "vendor": "Anvilogic", "category": "GRC"}
        }
    }


def transform(input):
    criteriaKey = "isComplianceMonitored"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        detections = data.get("results", data.get("data", data.get("items", data.get("detections", []))))

        if not isinstance(detections, list):
            return create_response(
                result={
                "isComplianceMonitored": False,
                "activeDetections": 0,
                "totalDetections": 0,
                "error": "Unexpected detections response format"
            },
                validation=validation,
                fail_reasons=["isComplianceMonitored check failed"]
            )
        total = len(detections)
        active = [
            d for d in detections
            if str(d.get("status", "")).lower() in ("active", "enabled", "deployed")
        ]
        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return create_response(

            result={
            "isComplianceMonitored": result,
            "activeDetections": len(active),
            "totalDetections": total
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
