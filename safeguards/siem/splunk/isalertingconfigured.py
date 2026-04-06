"""
Transformation: isAlertingConfigured
Vendor: Splunk
Category: SIEM

Evaluates isAlertingConfigured for Splunk SIEM
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAlertingConfigured", "vendor": "Splunk", "category": "SIEM"}
        }
    }


def transform(input):
    criteriaKey = "isAlertingConfigured"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # Splunk saved searches are under entry array
        entries = data.get("entry", data.get("entries", []))
        if not isinstance(entries, list):
            entries = []

        scheduled_count = 0

        for entry in entries:
            content = entry.get("content", entry)
            is_scheduled = content.get("is_scheduled", content.get("isScheduled", False))
            disabled = content.get("disabled", False)

            if (is_scheduled or str(is_scheduled) == "1") and not disabled:
                scheduled_count += 1

        # If we queried with is_scheduled=1 filter, all returned entries are scheduled
        if scheduled_count == 0 and len(entries) > 0:
            scheduled_count = len(entries)

        result = scheduled_count > 0

        return create_response(

            result={
            "isAlertingConfigured": result,
            "scheduledSearchCount": scheduled_count
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
