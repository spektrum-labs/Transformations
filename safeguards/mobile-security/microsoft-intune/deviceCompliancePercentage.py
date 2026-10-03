"""
Transformation: deviceCompliancePercentage
Vendor: Microsoft Intune  |  Category: Mobile Security

Criterion: the percentage of Intune-evaluated devices that are compliant with their compliance policies.

Data source: getDeviceComplianceStateSummary --
GET https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicyDeviceStateSummary
(https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicydevicestatesummary-get?view=graph-rest-1.0,
application permission DeviceManagementConfiguration.Read.All). One object, no paging.

  evaluated = compliant + nonCompliant + error + conflict + inGracePeriod + unknown   (notApplicable excluded)
  deviceCompliancePercentage = compliant / evaluated * 100, rounded DOWN to one decimal.

The summary is tenant-wide (all platforms Intune evaluates), not mobile-only; the counts are returned alongside.
Fails closed: an error body, missing integer counts, or zero evaluated devices returns None.
"""
import json
from datetime import datetime

KEY = "deviceCompliancePercentage"
VENDOR = "Microsoft Intune"
CATEGORY = "Mobile Security"


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


def entity(data):
    """A single-entity Graph GET is the object itself; Microsoft's doc samples wrap it in value."""
    if isinstance(data, dict) and isinstance(data.get("value"), dict):
        return data["value"]
    return data


FIELDS = ["compliantDeviceCount", "nonCompliantDeviceCount", "errorDeviceCount", "conflictDeviceCount",
          "inGracePeriodCount", "unknownDeviceCount"]


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Microsoft Graph returned an error for the compliance state summary", validation)
        data = entity(data)
        if not isinstance(data, dict):
            return not_measured("No deviceCompliancePolicyDeviceStateSummary was returned", validation)
        counts = {}
        for field in FIELDS:
            value = as_count(data.get(field))
            if value is None:
                return not_measured("The compliance state summary is missing " + field, validation)
            counts[field] = value
        evaluated = 0
        for field in FIELDS:
            evaluated = evaluated + counts[field]
        if evaluated <= 0:
            return not_measured("Intune has evaluated no devices against a compliance policy", validation)
        compliant = counts["compliantDeviceCount"]
        pct = ((compliant * 1000) // evaluated) / 10.0
        result = {KEY: pct, "evaluatedDeviceCount": evaluated}
        for field in FIELDS:
            result[field] = counts[field]
        line = str(compliant) + " of " + str(evaluated) + " evaluated devices (" + str(pct) + "%) are compliant"
        if compliant == evaluated:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=counts)
        return create_response(result=result, validation=validation, fail_reasons=[line], input_summary=counts,
                               recommendations=["Remediate the non-compliant, errored and unknown devices in Intune"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
