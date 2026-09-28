"""isEPPConfigured for Microsoft Defender for Endpoint, from the MDE machine inventory (GET /api/machines).

A whole-number percentage, floor(100 * configured / protected); the pass bar lives in the requirement.
protected = onboarded machines (servers included) that are not excluded and not unsupported;
configured = those whose sensor reports a healthy state. "Inactive" in MDE only means the machine has
not reported for 7 days or more, so it is counted as configured: staleness is never held against a
machine. The sensor fault states (ImpairedCommunication, NoSensorData, NoSensorDataImpairedCommunication,
Unknown) are not configured.

Not evaluated (dataCollection error, no value): an error or unrecognised body, a merged inventory that
still carries @odata.nextLink (pages left unread), or no onboarded machine to measure.

Separate file so the one-click transform's other keys (pinned at their own commit) are untouched.
"""

import json
from datetime import datetime


CONFIGURED_SENSOR_STATES = {"active", "inactive"}


def is_true(value):
    return value is True or (isinstance(value, str) and value.lower() == "true")


def extract_input(value):
    if isinstance(value, (str, bytes)):
        value = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    if isinstance(value, dict) and "data" in value and "validation" in value:
        return value["data"], value["validation"]
    data = value
    for _ in range(3):
        if not isinstance(data, dict):
            break
        nested = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), (dict, list)):
                nested = data[key]
                break
        if nested is None:
            break
        data = nested
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation, errors=(), passed=(), failed=(), summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": list(errors)},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {
                "passReasons": list(passed),
                "failReasons": list(failed) + list(errors),
                "recommendations": [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": "isEPPConfigured",
                "vendor": "Microsoft Defender for Endpoint",
                "category": "Endpoint Security",
            },
        },
    }


def measure(data):
    if not isinstance(data, dict) or "error" in data or "PSError" in data:
        raise ValueError("Microsoft did not return usable Endpoint evidence")
    machines = data.get("value")
    if not isinstance(machines, list):
        raise ValueError("MDE machines response must contain a value array")
    if any(not isinstance(machine, dict) for machine in machines):
        raise ValueError("MDE machines response contains an invalid machine record")
    next_link = data.get("@odata.nextLink")
    if isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"):
        raise ValueError("The machine inventory has more pages than were read (@odata.nextLink still present)")
    onboarded = [
        machine for machine in machines
        if not is_true(machine.get("isExcluded"))
        and str(machine.get("onboardingStatus") or "").lower() == "onboarded"
    ]
    if not onboarded:
        raise ValueError("No onboarded Defender for Endpoint machine was returned; there is nothing to measure")
    configured = [
        machine for machine in onboarded
        if str(machine.get("healthStatus") or "").lower() in CONFIGURED_SENSOR_STATES
    ]
    inactive = [machine for machine in configured if str(machine.get("healthStatus") or "").lower() == "inactive"]
    return {
        "isEPPConfigured": (len(configured) * 100) // len(onboarded),
        "protectedDevices": len(onboarded),
        "configuredDevices": len(configured),
        "inactiveDevices": len(inactive),
    }


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        result = measure(data)
        line = (
            f"{result['configuredDevices']} of {result['protectedDevices']} onboarded machines "
            f"({result['isEPPConfigured']}%) report a healthy sensor ({result['inactiveDevices']} inactive, counted)"
        )
        full = result["configuredDevices"] == result["protectedDevices"]
        return create_response(result, validation, passed=[line] if full else [], failed=[] if full else [line],
                               summary=result)
    except Exception as error:
        return create_response(
            {"isEPPConfigured": None},
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
