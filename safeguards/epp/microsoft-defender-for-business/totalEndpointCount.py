"""
Transformation: totalEndpointCount
Vendor: Microsoft Defender for Business  |  Category: Endpoint Security

Criterion: the number of endpoints protected by Defender for Business (onboarded devices).

Data source: getMachines --
GET https://api.securitycenter.microsoft.com/api/machines?$top=10000
(https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines, application permission
WindowsDefenderATP Machine.Read.All). Defender for Business uses the Defender for Endpoint API without
advanced hunting (https://learn.microsoft.com/en-us/defender-endpoint/api/apis-intro). One page holds up to
10,000 machines; Defender for Business is capped at 300 users. A response that still carries
@odata.nextLink is treated as partial and returns None.
Machine.onboardingStatus (https://learn.microsoft.com/en-us/defender-endpoint/api/machine): Onboarded,
CanBeOnboarded (discovered by device discovery, not protected), Unsupported, InsufficientInfo.

An empty list is a measured 0.
"""
import json
from datetime import datetime

KEY = "totalEndpointCount"
VENDOR = "Microsoft Defender for Business"
CATEGORY = "Endpoint Security"


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


def machine_counts(data):
    """(onboarded, can_be_onboarded, listed) from a machines list body, or None when it is not one."""
    if not isinstance(data, dict):
        return None
    machines = data.get("value")
    if not isinstance(machines, list) or data.get("@odata.nextLink"):
        return None
    onboarded = 0
    discovered = 0
    for machine in machines:
        if not isinstance(machine, dict) or not machine.get("id"):
            continue
        status = str(machine.get("onboardingStatus") or machine.get("onboardingstatus") or "").lower()
        if status == "onboarded":
            onboarded = onboarded + 1
        elif status == "canbeonboarded":
            discovered = discovered + 1
    return onboarded, discovered, len(machines)

def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Defender returned an error for the machines list", validation)
        counts = machine_counts(data)
        if counts is None:
            return not_measured("No complete machines list was returned", validation)
        onboarded = counts[0]
        discovered = counts[1]
        summary = {"onboardedDeviceCount": onboarded, "canBeOnboardedDeviceCount": discovered,
                   "listedDeviceCount": counts[2]}
        result = {KEY: onboarded, "canBeOnboardedDeviceCount": discovered}
        line = str(onboarded) + " devices are onboarded to Defender for Business"
        return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
