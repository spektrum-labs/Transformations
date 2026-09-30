"""
Transformation: isMdmManaged
Vendor: Microsoft Intune  |  Category: Mobile Security

Criterion: mobile devices are enrolled in and managed by Intune MDM.

Data source: getManagedDeviceOverview --
GET https://graph.microsoft.com/v1.0/deviceManagement/managedDeviceOverview
(https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddeviceoverview-get?view=graph-rest-1.0,
application permission DeviceManagementManagedDevices.Read.All). One object, no paging:
enrolledDeviceCount, mdmEnrolledCount and deviceOperatingSystemSummary.{iosCount, androidCount, ...}.

  managedMobileDeviceCount = iosCount + androidCount
  isMdmManaged = managedMobileDeviceCount > 0

What it proves: Intune manages N iOS/Android devices. What it cannot prove: that no unmanaged mobile device
exists (Intune only counts what is enrolled).
Fails closed: an error body, or an overview without integer OS counts, returns None.
"""
import json
from datetime import datetime

KEY = "isMdmManaged"
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


def entity(data):
    """A single-entity Graph GET is the object itself; Microsoft's doc samples wrap it in value."""
    if isinstance(data, dict) and isinstance(data.get("value"), dict):
        return data["value"]
    return data


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Microsoft Graph returned an error for managedDeviceOverview", validation)
        data = entity(data)
        summary = data.get("deviceOperatingSystemSummary") if isinstance(data, dict) else None
        if not isinstance(summary, dict):
            return not_measured("No managedDeviceOverview.deviceOperatingSystemSummary was returned", validation)
        ios = as_count(summary.get("iosCount"))
        android = as_count(summary.get("androidCount"))
        enrolled = as_count(data.get("enrolledDeviceCount"))
        if ios is None or android is None:
            return not_measured("The device overview is missing its iOS/Android counts", validation)
        mobile = ios + android
        result = {KEY: mobile > 0, "managedMobileDeviceCount": mobile, "iosCount": ios, "androidCount": android,
                  "enrolledDeviceCount": enrolled}
        line = "Intune manages " + str(mobile) + " mobile devices (" + str(ios) + " iOS, " + str(android) + " Android)"
        if mobile > 0:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=result)
        return create_response(result=result, validation=validation, fail_reasons=[line], input_summary=result,
                               recommendations=["Enroll corporate iOS and Android devices in Intune"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
