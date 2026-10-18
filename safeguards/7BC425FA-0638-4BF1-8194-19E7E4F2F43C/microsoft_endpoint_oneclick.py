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


# EDR server / workstation split, reported under new edr* keys only (rulings applied 2026-10-16). The live
# serverCoveragePercentage and totalServerCount below are criteria elsewhere and keep their old rule and
# values. For the edr* keys: osPlatform containing "server" is a server, and so is any Linux distribution;
# a Windows client version (Windows10, Windows11, ...) or macOS is a workstation. Anything else (iOS, Android, a missing or unknown value) is unclassified and counted
# in neither class.
LINUX_PLATFORMS = ("ubuntu", "debian", "centos", "rhel", "redhat", "fedora", "suse", "sles", "mint", "kali")
# Windows client builds by prefix, so variants such as Windows8Blue or Windows10WVD are covered too.
WINDOWS_CLIENT_PREFIXES = ("windows7", "windows8", "windows10", "windows11", "windowsxp", "windowsvista")


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
    for prefix in WINDOWS_CLIENT_PREFIXES:
        if platform.startswith(prefix):
            return "workstation"
    return None


def class_percentage(protected, total):
    """None when the class has no machine: no machines proves nothing, so it is never 0."""
    if total <= 0:
        return None
    # Floored to two decimals, never rounded: 100 only when every device in the class is protected,
    # and 94.9 can never be lifted to a 95 bar.
    return (10000 * protected // total) / 100


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
    servers = [machine for machine in eligible if "server" in str(machine.get("osPlatform") or "").lower()]
    protected_servers = [machine for machine in servers if str(machine.get("onboardingStatus") or "").lower() == "onboarded"]
    edr_servers = [machine for machine in eligible if os_class(machine) == "server"]
    edr_workstations = [machine for machine in eligible if os_class(machine) == "workstation"]
    edr_protected_servers = [m for m in edr_servers if str(m.get("onboardingStatus") or "").lower() == "onboarded"]
    edr_protected_workstations = [
        m for m in edr_workstations if str(m.get("onboardingStatus") or "").lower() == "onboarded"
    ]
    # A page that still has a next link is a partial read: the edr* fields are not measured on it.
    next_link = data.get("@odata.nextLink")
    edr_measured = bool(eligible) and not (
        isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"))
    edr_split = {
        "edrServerCoveragePercentage": class_percentage(len(edr_protected_servers), len(edr_servers)),
        "edrWorkstationCoveragePercentage": class_percentage(len(edr_protected_workstations), len(edr_workstations)),
        "edrTotalServerCount": len(edr_servers),
        "edrProtectedServerCount": len(edr_protected_servers),
        "edrTotalWorkstationCount": len(edr_workstations),
        "edrProtectedWorkstationCount": len(edr_protected_workstations),
        "edrUnclassifiedDeviceCount": len(eligible) - len(edr_servers) - len(edr_workstations),
    }
    if not edr_measured:
        edr_split = {key: None for key in edr_split}
    if not eligible:
        result = {
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
        }
        result.update(edr_split)
        return result
    coverage = round(100 * len(onboarded) / len(eligible))
    server_coverage = round(100 * len(protected_servers) / len(servers)) if servers else 0
    result = {
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
    result.update(edr_split)
    return result


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
            str(result["totalServerCount"]) + " eligible servers in the inventory ("
            + str(result["serverCoveragePercentage"]) + "% onboarded)",
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
