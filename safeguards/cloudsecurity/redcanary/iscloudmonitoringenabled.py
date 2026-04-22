"""
Transformation: isCloudMonitoringEnabled
Vendor: Red Canary
Category: Cloud Security / Monitoring

Validates that cloud monitoring is enabled by checking whether any
monitored endpoints exist. The API call filters by
monitoring_status=monitored, so any endpoints returned are actively
monitored.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return {"data": input_data.get("data"), "validation": input_data.get("validation")}
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data.get(key)
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return {"data": data, "validation": {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isCloudMonitoringEnabled",
                "vendor": "Red Canary",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isCloudMonitoringEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        extracted = extract_input(input)
        data = extracted.get("data")
        validation = extracted.get("validation")

        if validation.get("status") == "failed":
            has_data = (isinstance(data, list) and len(data) > 0) or \
                       (isinstance(data, dict) and ('data' in data or 'value' in data))
            if not has_data:
                return create_response(
                    result={criteriaKey: False},
                    validation=validation,
                    fail_reasons=["Input validation failed"]
                )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        endpoints = []

        if isinstance(data, list):
            endpoints = data
        elif isinstance(data, dict):
            if 'data' in data and isinstance(data.get('data'), list):
                endpoints = data.get('data')
            elif 'value' in data and isinstance(data.get('value'), list):
                endpoints = data.get('value')

        monitored_count = len(endpoints)
        monitoring_enabled = monitored_count > 0

        if monitoring_enabled:
            pass_reasons.append(
                f"Cloud monitoring is enabled: {monitored_count} endpoint(s) actively monitored"
            )
        else:
            fail_reasons.append("No monitored endpoints found")
            recommendations.append("Configure endpoint monitoring in Red Canary")

        return create_response(
            result={
                criteriaKey: monitoring_enabled,
                "monitoredEndpoints": monitored_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "monitoredEndpoints": monitored_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
