"""Microsoft one-click Endpoint evaluation from MDE machine inventory.

This stays separate from the legacy transforms so existing Endpoint customers
keep their current verdicts. A readable inventory with no eligible machine is Not evaluated (None,
"Defender has no onboarded devices"), never a fail; API and validation errors remain collection errors
instead of false positives.

Reasons: every result leads with what the inventory shows (onboarded / eligible machines, sensors
reporting, servers). Eligible machines with none onboarded is a finding for this tool (false / 0).
No eligible machine at all is an empty result and proves nothing, so it is None; the onboard-or-disconnect
hint is guidance only.
"""

import json
from datetime import datetime


HEALTHY_SENSOR_STATES = {"active"}


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


def create_response(result, validation, *, errors=(), summary=None, readings=(), recommendations=()):
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
                "passReasons": (list(readings) if passed else []) + [key + " passed" for key in passed],
                "failReasons": (list(readings) if failed else []) + [key + " failed" for key in failed] + list(errors),
                "recommendations": list(recommendations),
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


# Server / workstation split (additive; rulings applied 2026-10-16). osPlatform containing "server" is a
# server, and so is any Linux distribution; a Windows client version (Windows10, Windows11, ...) or macOS
# is a workstation. Anything else (iOS, Android, a missing or unknown value) is unclassified and counted
# in neither class.
LINUX_PLATFORMS = ("ubuntu", "debian", "centos", "rhel", "redhat", "fedora", "suse", "sles", "mint", "kali")
WINDOWS_CLIENT_VERSIONS = ("7", "8", "8.1", "10", "11", "vista", "xp")


def os_class(machine):
    """The class of a machine: "server", "workstation", or None (unclassified)."""
    if not isinstance(machine, dict):
        return None
    platform = str(machine.get("osPlatform") or "").strip().lower().replace(" ", "")
    if not platform:
        return None
    if "server" in platform or "linux" in platform:
        return "server"
    for distribution in LINUX_PLATFORMS:
        if platform.startswith(distribution):
            return "server"
    if platform.startswith("mac"):
        return "workstation"
    if platform.startswith("windows") and platform[len("windows"):] in WINDOWS_CLIENT_VERSIONS:
        return "workstation"
    return None


def class_percentage(protected, total):
    """None when the class has no machine: no machines proves nothing, so it is never 0."""
    if total <= 0:
        return None
    return round(100 * protected / total)

def evaluate_machines(data):
    machines = data.get("value") if isinstance(data, dict) else None
    if not isinstance(machines, list):
        raise ValueError("MDE machines response must contain a value array")
    if any(not isinstance(machine, dict) for machine in machines):
        raise ValueError("MDE machines response contains an invalid machine record")
    non_excluded = [machine for machine in machines if not is_true(machine.get("isExcluded"))]
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
    servers = [machine for machine in eligible if os_class(machine) == "server"]
    protected_servers = [machine for machine in servers if str(machine.get("onboardingStatus") or "").lower() == "onboarded"]
    workstations = [machine for machine in eligible if os_class(machine) == "workstation"]
    protected_workstations = [
        machine for machine in workstations if str(machine.get("onboardingStatus") or "").lower() == "onboarded"
    ]
    unclassified = len(eligible) - len(servers) - len(workstations)
    if not eligible:
        return {
            "isEPPEnabled": None,
            "isEPPConfigured": None,
            "isEPPLoggingEnabled": None,
            "requiredCoveragePercentage": None,
            "serverCoveragePercentage": None,
            "totalEndpointCount": 0,
            "totalServerCount": 0,
            "eligibleDevices": 0,
            "protectedDevices": 0,
            "reportingDevices": 0,
            "workstationCoveragePercentage": None,
            "protectedServerCount": None,
            "totalWorkstationCount": None,
            "protectedWorkstationCount": None,
            "unclassifiedDeviceCount": None,
        }
    coverage = round(100 * len(onboarded) / len(eligible))
    # No server is None (no servers proves nothing), never 0.
    server_coverage = class_percentage(len(protected_servers), len(servers))
    # A page that still has a next link is a partial read: the new split fields are not measured on it.
    next_link = data.get("@odata.nextLink")
    partial = isinstance(next_link, str) and next_link.strip() not in ("", "None", "null")
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
        "workstationCoveragePercentage": None if partial else class_percentage(len(protected_workstations), len(workstations)),
        "protectedServerCount": None if partial else len(protected_servers),
        "totalWorkstationCount": None if partial else len(workstations),
        "protectedWorkstationCount": None if partial else len(protected_workstations),
        "unclassifiedDeviceCount": None if partial else unclassified,
    }


def seen_in_inventory(count):
    if count:
        return " (" + str(count) + " eligible machines in its inventory, none onboarded)"
    return " (its machine inventory is empty)"


def describe(result):
    """Human-readable readings of the inventory; values are never changed here."""
    eligible = result["eligibleDevices"]
    onboarded = result["protectedDevices"]
    if onboarded == 0:
        return (
            ["Defender for Endpoint is connected and has 0 onboarded devices" + seen_in_inventory(eligible)
             + ", so it protects no endpoint or server"],
            ["Onboard the organisation's devices to Defender for Endpoint (Microsoft Defender portal, "
             "Settings > Endpoints > Device management > Onboarding), or disconnect this integration if another endpoint tool protects them"],
        )
    return (
        [
            str(onboarded) + " of " + str(eligible) + " eligible machines are onboarded to Defender for Endpoint ("
            + str(result["requiredCoveragePercentage"]) + "%)",
            str(result["reportingDevices"]) + " of " + str(onboarded) + " onboarded machines report an active sensor",
            # Text kept as before: with no server the value is None, and the reading still says 0%.
            str(result["totalServerCount"]) + " eligible servers in the inventory ("
            + str(result["serverCoveragePercentage"] or 0) + "% onboarded)",
        ],
        [],
    )


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        if not isinstance(data, dict) or "error" in data or "PSError" in data:
            raise ValueError("Microsoft did not return usable Endpoint evidence")

        if isinstance(data.get("value"), list):
            result = evaluate_machines(data)
        else:
            raise ValueError("Unrecognized Microsoft Endpoint response shape")
        if result["eligibleDevices"] == 0:
            return create_response(result, validation, errors=["Defender has no onboarded devices"],
                                   summary={"returnedKeys": sorted(result)}, recommendations=describe(result)[1])
        readings, recommendations = describe(result)
        return create_response(result, validation, summary={"returnedKeys": sorted(result)},
                               readings=readings, recommendations=recommendations)
    except Exception as error:
        return create_response(
            {},
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
