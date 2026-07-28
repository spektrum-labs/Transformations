"""Microsoft one-click Endpoint evaluation from MDE machine inventory.

This stays separate from the legacy transforms so existing Endpoint customers
keep their current verdicts. Valid empty Microsoft responses evaluate to false/0;
API and validation errors remain collection errors instead of false positives.
"""

import json
from datetime import datetime


HEALTHY_SENSOR_STATES = {"active"}


def _is_true(value):
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _extract(value):
    if isinstance(value, (str, bytes)):
        value = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    if isinstance(value, dict) and "data" in value and "validation" in value:
        return value["data"], value["validation"]
    data = value
    for _ in range(3):
        if not isinstance(data, dict):
            break
        nested = next(
            (data[key] for key in ("api_response", "response", "result", "apiResponse", "Output")
             if isinstance(data.get(key), (dict, list))),
            None,
        )
        if nested is None:
            break
        data = nested
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def _response(result, validation, *, errors=(), summary=None):
    passed = [key for key, value in result.items() if isinstance(value, bool) and value]
    failed = [key for key, value in result.items() if isinstance(value, bool) and not value]
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
                "passReasons": [key + " passed" for key in passed],
                "failReasons": [key + " failed" for key in failed] + list(errors),
                "recommendations": [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": "microsoft_endpoint_oneclick",
                "vendor": "Microsoft Defender for Endpoint",
                "category": "Endpoint Security",
            },
        },
    }


def _machines(data):
    machines = data.get("value") if isinstance(data, dict) else None
    if not isinstance(machines, list):
        raise ValueError("MDE machines response must contain a value array")
    if any(not isinstance(machine, dict) for machine in machines):
        raise ValueError("MDE machines response contains an invalid machine record")
    non_excluded = [machine for machine in machines if not _is_true(machine.get("isExcluded"))]
    eligible = [
        machine for machine in non_excluded
        if str(machine.get("onboardingStatus") or "").lower() not in {"unsupported", "insufficientinfo"}
    ]
    onboarded = [machine for machine in eligible if str(machine.get("onboardingStatus") or "").lower() == "onboarded"]
    reporting = [
        machine for machine in onboarded
        if machine.get("lastSeen")
        and str(machine.get("healthStatus") or "").lower() in HEALTHY_SENSOR_STATES
    ]
    servers = [machine for machine in eligible if "server" in str(machine.get("osPlatform") or "").lower()]
    protected_servers = [machine for machine in servers if str(machine.get("onboardingStatus") or "").lower() == "onboarded"]
    coverage = round(100 * len(onboarded) / len(eligible)) if eligible else 0
    server_coverage = round(100 * len(protected_servers) / len(servers)) if servers else 0
    return {
        "isEPPEnabled": bool(onboarded),
        "isEPPConfigured": bool(eligible) and len(onboarded) == len(eligible),
        "isEPPLoggingEnabled": bool(onboarded) and len(reporting) == len(onboarded),
        "requiredCoveragePercentage": coverage,
        "serverCoveragePercentage": server_coverage,
        "totalEndpointCount": len(eligible),
        "totalServerCount": len(servers),
        "eligibleDevices": len(eligible),
        "protectedDevices": len(onboarded),
        "reportingDevices": len(reporting),
    }


def transform(input):
    try:
        data, validation = _extract(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        if not isinstance(data, dict) or "error" in data or "PSError" in data:
            raise ValueError("Microsoft did not return usable Endpoint evidence")

        if isinstance(data.get("value"), list):
            result = _machines(data)
        else:
            raise ValueError("Unrecognized Microsoft Endpoint response shape")
        return _response(result, validation, summary={"returnedKeys": sorted(result)})
    except Exception as error:
        return _response(
            {},
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
