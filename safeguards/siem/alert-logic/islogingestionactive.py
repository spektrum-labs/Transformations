"""
Transformation: isLogIngestionActive
Vendor: Alert Logic
Category: SIEM

Evaluates isLogIngestionActive for Alert Logic
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isLogIngestionActive", "vendor": "Alert Logic", "category": "SIEM"}
        }
    }


def transform(input):
    criteriaKey = "isLogIngestionActive"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        sources = data.get("sources", data.get("data", data.get("items", [])))
        if isinstance(sources, dict):
            sources = list(sources.values()) if sources else []
        if not isinstance(sources, list):
            return create_response(
                result={
                "isLogIngestionActive": False,
                "activeSources": 0,
                "totalSources": 0,
                "error": "Unexpected sources response format"
            },
                validation=validation,
                fail_reasons=["isLogIngestionActive check failed"]
            )
        total = len(sources)
        active = [
            s for s in sources
            if str(s.get("status", "")).lower() in {"ok", "active", "enabled", "collecting"}
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return create_response(

            result={
            "isLogIngestionActive": result,
            "activeSources": len(active),
            "totalSources": total
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
