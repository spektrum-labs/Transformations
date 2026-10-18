"""
Transformation: requiredCoveragePercentage
Vendor: Microsoft Defender / Endpoint Protection
Category: Endpoint Security

Evaluates percentage of endpoint protection coverage for eligible machines.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None,
                    exposure=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    response = {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "requiredCoveragePercentage",
                "vendor": "Microsoft Defender",
                "category": "Endpoint Security"
            }
        }
    }
    if exposure is not None:
        response["additionalInfo"]["exposure"] = exposure
    return response


# EDR server / workstation split, under new edr* keys (additive; rulings applied 2026-10-16). osPlatform containing "server" is a
# server, and so is any Linux distribution; a Windows client version (Windows10, Windows11, ...) or macOS
# is a workstation. Anything else (iOS, Android, a missing or unknown value) is unclassified and counted
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

# Every split field, None: what a partial, failed or empty read reports instead of a confident number.
SPLIT_NOT_MEASURED = {
    "edrServerCoveragePercentage": None,
    "edrWorkstationCoveragePercentage": None,
    "edrTotalServerCount": None,
    "edrProtectedServerCount": None,
    "edrTotalWorkstationCount": None,
    "edrProtectedWorkstationCount": None,
    "edrUnclassifiedDeviceCount": None,
}


def with_split_not_measured(result):
    merged = dict(result)
    merged.update(SPLIT_NOT_MEASURED)
    return merged


def coverage_split(eligible_machines):
    """The split over the machines requiredCoveragePercentage divides by, protected meaning Onboarded."""
    servers = 0
    protected_servers = 0
    workstations = 0
    protected_workstations = 0
    unclassified = 0
    for machine in eligible_machines:
        kind = os_class(machine)
        onboarded = machine.get("onboardingStatus") == "Onboarded"
        if kind == "server":
            servers = servers + 1
            if onboarded:
                protected_servers = protected_servers + 1
        elif kind == "workstation":
            workstations = workstations + 1
            if onboarded:
                protected_workstations = protected_workstations + 1
        else:
            unclassified = unclassified + 1
    return {
        "edrServerCoveragePercentage": class_percentage(protected_servers, servers),
        "edrWorkstationCoveragePercentage": class_percentage(protected_workstations, workstations),
        "edrTotalServerCount": servers,
        "edrProtectedServerCount": protected_servers,
        "edrTotalWorkstationCount": workstations,
        "edrProtectedWorkstationCount": protected_workstations,
        "edrUnclassifiedDeviceCount": unclassified,
    }


def not_evaluated(validation, reason, recommendations=None, input_summary=None):
    """Not evaluated: the criterion is None and dataCollection carries the reason."""
    return create_response(
        result=with_split_not_measured({
            "requiredCoveragePercentage": None,
            "allDevicesPercentageofCoverage": None,
            "eligibleDevicesPercentageofCoverage": None,
        }),
        validation=validation,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=[reason]
    )


def transform(input):
    criteriaKey = "requiredCoveragePercentage"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result=with_split_not_measured({criteriaKey: None}),
                validation=validation,
                api_errors=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Get machine data from value array. A body with no machine list at all (an API error
        # envelope, an empty object) read nothing, so it is Not evaluated rather than "no devices".
        machine_data = None
        if isinstance(data, dict) and isinstance(data.get('value'), list):
            machine_data = data['value']
        elif isinstance(data, list):
            machine_data = data

        if machine_data is None:
            return not_evaluated(validation, "Defender returned no machine inventory to read")

        # A page that still has a next link is a partial read: its percentage is not the fleet's.
        next_link = data.get("@odata.nextLink") if isinstance(data, dict) else None
        if isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"):
            return not_evaluated(
                validation,
                "The machine inventory has more pages than were read (@odata.nextLink still present)")

        # Exclude devices marked as excluded
        non_excluded = [m for m in machine_data if isinstance(m, dict) and str(m.get("isExcluded", "false")).lower() != "true"]

        # Eligible = devices that can run endpoint protection (exclude Unsupported and InsufficientInfo)
        ineligible_statuses = {"Unsupported", "InsufficientInfo"}
        eligibleMachines = [m for m in non_excluded if m.get("onboardingStatus") not in ineligible_statuses]

        # Protected = onboarded devices (Active or Inactive — Inactive just means powered off)
        protectedMachines = [m for m in eligibleMachines if m.get("onboardingStatus") == "Onboarded"]

        allDevices = len(machine_data)
        eligibleDevices = len(eligibleMachines)
        protectedDevices = len(protectedMachines)

        # Why each device is outside the eligible population. These are not alike: an Unsupported
        # device is often not an endpoint at all (network gear, IoT), while an InsufficientInfo device
        # may be an unmanaged workstation and an excluded one was hidden from this figure by an
        # admin. Reported in additionalInfo.exposure only, never in transformedResponse and never scored:
        # requiredCoveragePercentage still divides by eligible devices.
        excludedDevices = len([m for m in machine_data if isinstance(m, dict) and str(m.get("isExcluded", "false")).lower() == "true"])
        unsupportedDevices = len([m for m in non_excluded if m.get("onboardingStatus") == "Unsupported"])
        insufficientInfoDevices = len([m for m in non_excluded if m.get("onboardingStatus") == "InsufficientInfo"])
        unreadableDevices = len([m for m in machine_data if not isinstance(m, dict)])

        allDevicesPercentage = round((protectedDevices / allDevices) * 100) if allDevices > 0 else 0
        eligibleDevicesPercentage = round((protectedDevices / eligibleDevices) * 100) if eligibleDevices > 0 else 0

        # No eligible device is an empty read, not full coverage: 0 of 0 proves nothing, so the
        # criterion is Not evaluated (None plus a dataCollection error), never 100.
        if eligibleDevices == 0:
            return not_evaluated(
                validation, "Defender has no onboarded devices",
                recommendations=["Ensure devices are properly enrolled and not excluded"],
                input_summary={"allDevices": allDevices, "eligibleDevices": 0, "protectedDevices": 0})

        criteriaValue = eligibleDevicesPercentage

        if criteriaValue >= 100:
            pass_reasons.append(f"All eligible devices are protected: {protectedDevices}/{eligibleDevices} (100%)")
        else:
            fail_reasons.append(f"Not all eligible devices are protected: {protectedDevices}/{eligibleDevices} ({eligibleDevicesPercentage}%)")
            recommendations.append("Onboard remaining eligible devices to endpoint protection")

        pass_reasons.append(f"Overall coverage: {protectedDevices}/{allDevices} total devices ({allDevicesPercentage}%)")
        if allDevices != eligibleDevices:
            ineligible = allDevices - eligibleDevices
            pass_reasons.append(f"{ineligible} device(s) excluded from eligibility (Unsupported/InsufficientInfo)")

        result = {
            criteriaKey: criteriaValue,
            "allDevicesPercentageofCoverage": allDevicesPercentage,
            "eligibleDevicesPercentageofCoverage": eligibleDevicesPercentage,
            "allDevices": allDevices,
            "eligibleDevices": eligibleDevices,
            "protectedDevices": protectedDevices
        }
        result.update(coverage_split(eligibleMachines))

        # The population this number divides by, declared by the transform that computed it, so a
        # reader of the result never has to infer the denominator.
        exposure = {
            "criteriaKey": criteriaKey,
            "exposureClass": "coverage",
            "population": ("eligible endpoints: devices in the Defender inventory that are not excluded "
                           "and whose onboardingStatus is not Unsupported or InsufficientInfo"),
            "coveredRule": "onboardingStatus Onboarded (Active or Inactive)",
            "denominator": eligibleDevices,
            "covered": protectedDevices,
            "inventoryTotal": allDevices,
            "outOfModel": {
                "excluded": excludedDevices,
                "unsupported": unsupportedDevices,
                "insufficientInfo": insufficientInfoDevices,
                "unreadable": unreadableDevices,
            },
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "allDevices": allDevices,
                "eligibleDevices": eligibleDevices,
                "protectedDevices": protectedDevices
            },
            exposure=exposure
        )

    except Exception as e:
        # An error is Not evaluated, never a fail: None plus a dataCollection error.
        return create_response(
            result=with_split_not_measured({criteriaKey: None}),
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            api_errors=[f"Transformation error: {str(e)}"]
        )
