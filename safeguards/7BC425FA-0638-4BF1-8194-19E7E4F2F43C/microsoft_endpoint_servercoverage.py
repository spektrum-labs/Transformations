"""serverCoveragePercentage for Microsoft Defender for Endpoint (One-Click), from the MDE machine inventory
(GET /api/machines).

Why a separate file: microsoft_endpoint_oneclick.py (pinned for its other keys) returns 0 when the
inventory holds no server at all, so a tenant whose MDE sees only workstations or phones failed
"servers covered" with nothing to measure (Infraservices, Orion Steel, ReSRG on 2026-09-29).

Eligibility matches microsoft_endpoint_oneclick.py: not excluded, onboardingStatus not Unsupported or
InsufficientInfo. A server is an eligible machine whose osPlatform names a server.
Value: round(100 * onboarded servers / eligible servers); the pass bar lives in the requirement.

Not evaluated (dataCollection error, value None): an error or unrecognised body, an inventory that
still carries @odata.nextLink (pages left unread), or an inventory with no server.
"""

import json
from datetime import datetime


KEYS = ("serverCoveragePercentage",)


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
                "transformationId": "serverCoveragePercentage",
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


def measure(machines):
    eligible = [
        machine for machine in machines
        if not is_true(machine.get("isExcluded"))
        and str(machine.get("onboardingStatus") or "").lower() not in ("unsupported", "insufficientinfo")
    ]
    servers = [machine for machine in eligible if "server" in str(machine.get("osPlatform") or "").lower()]
    protected_servers = [machine for machine in servers if str(machine.get("onboardingStatus") or "").lower() == "onboarded"]
    return {
        "serverCoveragePercentage": round(100 * len(protected_servers) / len(servers)) if servers else None,
        "totalServerCount": len(servers),
        "onboardedServerCount": len(protected_servers),
    }


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        result = measure(read_inventory(data))
        errors = []
        if result["serverCoveragePercentage"] is None:
            errors.append("The MDE inventory holds no server; there is no server coverage to measure")
        line = f"{result['onboardedServerCount']} of {result['totalServerCount']} servers onboarded to MDE"
        summary = dict(result)
        summary["reading"] = line
        return create_response(result, validation, errors=errors, summary=summary)
    except Exception as error:
        result = {}
        for key in KEYS:
            result[key] = None
        return create_response(
            result,
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
