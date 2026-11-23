"""isEPPDeployed for Arctic Wolf Aurora Endpoint Defense (the Aurora Protect Desktop agent).

Input: the extended device list, GET {baseURL}/devices/v2/extended (scope device:list), read through the
paging envelope: page_items[], plus total_number_of_items. The vendor documents agent_version on each device
as the installed Aurora Protect Desktop agent version. Page:
https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api/device-api/get-devices-extended

True when at least one device reports an agent version. A device is only in this list because the agent
registered with the console, so this proves the agent is deployed, not on what share of the estate (the API
cannot see endpoints that never enrolled).

The plain device list (GET /devices/v2) has no agent_version. When devices come back and not one record has
the field at all, the reply is the wrong view and proves nothing: a data-collection error (Not evaluated),
never False.
"""

import json
from datetime import datetime

DOCS = "https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api/device-api/get-devices-extended"


def unwrap(value):
    """The engine hands the method's response in one of a few envelopes; peel them, never invent data."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if isinstance(value, bytes):
        try:
            value = json.loads(value.decode("utf-8"))
        except ValueError:
            return None
    if isinstance(value, dict) and "data" in value and "validation" in value:
        value = value.get("data")
    for unused in range(3):
        if isinstance(value, dict):
            for key in ("apiResponse", "api_response", "response", "result", "Output"):
                if key in value and isinstance(value.get(key), (dict, list)):
                    value = value[key]
                    break
            else:
                break
    return value


def devices(body):
    """The device records, or None when the reply is not a device list."""
    if isinstance(body, dict):
        body = body.get("page_items")
    if isinstance(body, list):
        return [d for d in body if isinstance(d, dict)]
    return None


def has_agent_version(device):
    version = device.get("agent_version")
    return isinstance(version, str) and bool(version.strip())


def response(key, passed, summary, pass_reasons=None, fail_reasons=None, errors=None):
    return {
        "transformedResponse": {key: bool(passed)},
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors or []},
            "validation": {"status": "passed" if not errors else "failed", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": key, "vendor": "Arctic Wolf Aurora (Cylance)", "category": "Endpoint Security",
                         "source": DOCS},
        },
    }


def transform(input):
    key = "isEPPDeployed"
    found = devices(unwrap(input))
    if found is None:
        return response(key, False, {}, fail_reasons=["No device list returned"], errors=["unreadable response"])
    if found and not any("agent_version" in d for d in found):
        return response(key, False, {"devices": len(found)}, fail_reasons=["Device records carry no agent_version"],
                        errors=["agent_version missing from every device: not the extended device list"])
    deployed = [d for d in found if has_agent_version(d)]
    summary = {"devices": len(found), "devicesWithAgent": len(deployed)}
    if deployed:
        return response(key, True, summary,
                        pass_reasons=[f"Aurora agent installed on {len(deployed)} of {len(found)} device(s) read"])
    return response(key, False, summary, fail_reasons=["No device reports an installed Aurora agent"])
