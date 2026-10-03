"""
Transformation: openHighSeverityAlertCount
Vendor: Microsoft Defender for Cloud Apps  |  Category: Cloud Security

Criterion: the number of open (new or inProgress) High severity Defender for Cloud Apps alerts.

Data source: getOpenHighSeverityAlerts (Microsoft One-Click, certificate sign-in, no client secret) --
GET https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=serviceSource eq 'microsoftDefenderForCloudApps'
and severity eq 'high' and (status eq 'new' or status eq 'inProgress')
(https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0,
application permission SecurityAlert.Read.All). Integration-Service follows @odata.nextLink and merges every
page into value; the count is the number of alerts in value.

Fails closed (returns None): an error body (403 before re-consent, 429 after retries, IS pagination_incomplete),
no value list, a remaining @odata.nextLink (pages were not all read), or any alert outside the filter
(missing or different serviceSource / severity / status: an unexpected body is never counted as zero).
"""
import json
from datetime import datetime

KEY = "openHighSeverityAlertCount"
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
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


OPEN_STATUSES = ("new", "inprogress")


def open_high_total(data):
    """Number of open High Defender for Cloud Apps alerts, or None when the list cannot be trusted."""
    if not isinstance(data, dict) or not isinstance(data.get("value"), list):
        return None
    if data.get("@odata.nextLink"):
        return None
    total = 0
    for alert in data["value"]:
        if not isinstance(alert, dict):
            return None
        source = str(alert.get("serviceSource") or "").lower()
        severity = str(alert.get("severity") or "").lower()
        status = str(alert.get("status") or "").lower()
        if source != "microsoftdefenderforcloudapps" or severity != "high" or status not in OPEN_STATUSES:
            return None
        total = total + 1
    return total

def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Microsoft Graph returned an error for the Defender for Cloud Apps alerts list", validation)
        total = open_high_total(data)
        if total is None:
            return not_measured("No complete Defender for Cloud Apps alert list was returned", validation)
        summary = {"openHighSeverityAlertCount": total}
        line = str(total) + " open High severity alerts in Defender for Cloud Apps"
        result = {KEY: total}
        if total == 0:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=summary)
        return create_response(result=result, validation=validation, fail_reasons=[line], input_summary=summary,
                               recommendations=["Investigate and close the open High severity alerts"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
