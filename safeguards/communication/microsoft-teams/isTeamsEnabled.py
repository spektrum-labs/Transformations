"""
Transformation: isTeamsEnabled
Vendor: Microsoft Teams  |  Category: Communication

Criterion: Microsoft Teams is enabled for the organization.

Data source: getTeamwork --
GET https://graph.microsoft.com/v1.0/teamwork
(https://learn.microsoft.com/en-us/graph/api/teamwork-get?view=graph-rest-1.0, application permission
Teamwork.Read.All). Returns {id: "teamwork", isTeamsEnabled, region}.

Fails closed: an error body, or a body without a boolean isTeamsEnabled, returns None.
"""
import json
from datetime import datetime

KEY = "isTeamsEnabled"
VENDOR = "Microsoft Teams"
CATEGORY = "Communication"


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


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Microsoft Graph returned an error for teamwork", validation)
        if isinstance(data, dict) and isinstance(data.get("value"), dict):
            data = data["value"]
        enabled = data.get("isTeamsEnabled") if isinstance(data, dict) else None
        if not isinstance(enabled, bool):
            return not_measured("The teamwork object carries no isTeamsEnabled flag", validation)
        result = {KEY: enabled, "region": data.get("region")}
        if enabled:
            return create_response(result=result, validation=validation, input_summary=result,
                                   pass_reasons=["Microsoft Teams is enabled for the organization"])
        return create_response(result=result, validation=validation, input_summary=result,
                               fail_reasons=["Microsoft Teams is not enabled for the organization"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
