"""
Transformation: noHighFindings
Vendor: Microsoft Defender for Cloud Apps  |  Category: Cloud Security

Criterion: there is no open High severity Defender for Cloud Apps alert.

Data source: getOpenHighSeverityAlerts --
POST {apiUrl}/api/v1/alerts/ with body
{"filters": {"alertOpen": {"eq": true}, "severity": {"eq": [2]}}, "limit": 1}
(list call, read-only; https://learn.microsoft.com/en-us/defender-cloud-apps/api-alerts-list, filters on
https://learn.microsoft.com/en-us/defender-cloud-apps/api-alerts: severity 2 = High, alertOpen = not closed).
Application permission: Microsoft Cloud App Security Investigation.read
(https://learn.microsoft.com/en-us/defender-cloud-apps/api-authentication-application).
The response carries {data, hasNext, total, moreThanTotal}; total is the full match count, so no paging.
Fails closed: an error body, a missing or non-integer total, or moreThanTotal true (total is only a lower
bound) returns None.
True only when the exact count is 0.
"""
import json
from datetime import datetime

KEY = "noHighFindings"
VENDOR = "Microsoft Defender for Cloud Apps"
CATEGORY = "Cloud Security"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_measured(reason, validation=None):
    return create_response(result={KEY: None}, validation=validation, api_errors=[reason], fail_reasons=[reason])


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value == int(value) and value >= 0:
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def is_error_body(data):
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors"):
        return True
    status = data.get("statusCode") or data.get("status_code") or data.get("status")
    if isinstance(status, int) and status >= 400:
        return True
    return False


def load(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        input = json.loads(input) if input.strip() else None
    return extract_input(input)


def open_high_total(data):
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        return None
    if data.get("moreThanTotal") is True:
        return None
    return as_count(data.get("total"))

def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Defender for Cloud Apps returned an error for the alerts list", validation)
        total = open_high_total(data)
        if total is None:
            return not_measured("No exact open High alert count was returned", validation)
        summary = {"openHighSeverityAlertCount": total}
        line = str(total) + " open High severity alerts in Defender for Cloud Apps"
        result = {KEY: total == 0, "openHighSeverityAlertCount": total}
        if total == 0:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=summary)
        return create_response(result=result, validation=validation, fail_reasons=[line], input_summary=summary,
                               recommendations=["Investigate and close the open High severity alerts"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
