"""
Transformation: isContinuousMonitoringEnabled
Vendor: Lacework
Category: Cloud Security

Evaluates isContinuousMonitoringEnabled for Lacework (FortiCNAPP)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isContinuousMonitoringEnabled", "vendor": "Lacework", "category": "Cloud Security"}
        }
    }


def transform(input):
    criteriaKey = "isContinuousMonitoringEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        channels = data.get("data", data.get("alertChannels", data.get("results", data.get("items", []))))

        if not isinstance(channels, list):
            return create_response(
                result={
                "isContinuousMonitoringEnabled": False,
                "activeChannels": 0,
                "totalChannels": 0,
                "error": "Unexpected alert channels response format"
            },
                validation=validation,
                fail_reasons=["isContinuousMonitoringEnabled check failed"]
            )
        total = len(channels)

        active = [
            c for c in channels
            if c.get("enabled", False) is True
            or str(c.get("enabled", "")).lower() in ("true", "1")
            or str(c.get("state", "")).lower() in ("enabled", "active")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return create_response(

            result={
            "isContinuousMonitoringEnabled": result,
            "activeChannels": len(active),
            "totalChannels": total
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
