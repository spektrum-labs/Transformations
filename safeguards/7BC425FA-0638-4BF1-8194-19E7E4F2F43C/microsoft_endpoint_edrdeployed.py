"""isEDRDeployed and isEPPDeployed for Microsoft Defender for Endpoint (One-Click), from the MDE machine
inventory (GET /api/machines).

Why a separate file: the One-Click definition ran epp_transform.py (a Sophos-shaped reader of
"items"/"assignedProducts") on the MDE alerts list for both keys, so both read false at every tenant,
including tenants with thousands of onboarded machines (2026-09-29).

Value: true when at least one eligible machine (not excluded, onboardingStatus not Unsupported or
InsufficientInfo) is onboarded to MDE, whose sensor is the EDR and whose Defender AV platform is the
EPP; false when machines are eligible but none is onboarded. How much of the estate is covered is
requiredCoveragePercentage, a number, not this flag.

Not evaluated (dataCollection error, values None): an error or unrecognised body, an inventory that
still carries @odata.nextLink (pages left unread), or an inventory with no eligible machine at all
("Defender has no onboarded devices"). An empty result proves nothing about the estate, so it is never
a fail; the onboard-or-disconnect hint is guidance only.
"""

import json
from datetime import datetime


KEYS = ("isEDRDeployed", "isEPPDeployed")


def is_true(value):
    return value is True or (isinstance(value, str) and value.lower() == "true")


def extract_input(value):
    if isinstance(value, (str, bytes)):
        value = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    if isinstance(value, dict) and "data" in value and "validation" in value:
        return value["data"], value["validation"]
    data = value
    for attempt in range(3):
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


def create_response(result, validation, errors=(), passed=(), failed=(), summary=None, recommendations=()):
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
                "recommendations": list(recommendations),
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": "microsoft_endpoint_edrdeployed",
                "vendor": "Microsoft Defender for Endpoint",
                "category": "Endpoint Security",
            },
        },
    }


def read_inventory(data):
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
    return machines


def seen_in_inventory(count):
    if count:
        return " (" + str(count) + " eligible machines in its inventory, none onboarded)"
    return " (its machine inventory is empty)"


def measure(machines):
    eligible = [
        machine for machine in machines
        if not is_true(machine.get("isExcluded"))
        and str(machine.get("onboardingStatus") or "").lower() not in ("unsupported", "insufficientinfo")
    ]
    onboarded = [machine for machine in eligible if str(machine.get("onboardingStatus") or "").lower() == "onboarded"]
    deployed = len(onboarded) > 0
    result = {
        "isEDRDeployed": deployed,
        "isEPPDeployed": deployed,
        "eligibleDevices": len(eligible),
        "onboardedDevices": len(onboarded),
    }
    return result


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        result = measure(read_inventory(data))
        errors = []
        if result["eligibleDevices"] == 0:
            return create_response(
                {key: None for key in KEYS}, validation, errors=["Defender has no onboarded devices"],
                summary=dict(result), recommendations=[
                "Onboard the organisation's devices to Defender for Endpoint (Microsoft Defender portal, Settings > "
                "Endpoints > Device management > Onboarding), or disconnect this integration if another endpoint "
                "tool protects them"])
        line = f"{result['onboardedDevices']} of {result['eligibleDevices']} eligible machines onboarded to MDE"
        summary = dict(result)
        summary["reading"] = line
        if result["isEDRDeployed"]:
            return create_response(result, validation, errors=errors, summary=summary,
                                   passed=[line.replace("to MDE", "to Defender for Endpoint")])
        zero = ("Defender for Endpoint is connected and has 0 onboarded devices"
                + seen_in_inventory(result["eligibleDevices"]) + ", so its EDR sensor and antivirus protect no device")
        return create_response(result, validation, errors=errors, summary=summary, failed=[zero], recommendations=[
                "Onboard the organisation's devices to Defender for Endpoint (Microsoft Defender portal, Settings > "
                "Endpoints > Device management > Onboarding), or disconnect this integration if another endpoint "
                "tool protects them"])
    except Exception as error:
        result = {}
        for key in KEYS:
            result[key] = None
        return create_response(
            result,
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
