import json
import re
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    data = input_data
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}

    for _ in range(3):
        if not isinstance(data, dict):
            break
        unwrapped = False
        for key in ["api_response", "response", "result", "apiResponse", "Output"]:
            if key in data and isinstance(data.get(key), (dict, list)):
                data = data[key]
                unwrapped = True
                break
        if not unwrapped:
            break

    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    if pass_reasons is None:
        pass_reasons = []
    if fail_reasons is None:
        fail_reasons = []
    if recommendations is None:
        recommendations = []
    if transformation_errors is None:
        transformation_errors = []
    if api_errors is None:
        api_errors = []
    if additional_findings is None:
        additional_findings = []
    if input_summary is None:
        input_summary = {}

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if api_errors else "success",
                "errors": api_errors
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors,
                "inputSummary": input_summary
            },
            "evaluation": {
                "passReasons": pass_reasons,
                "failReasons": fail_reasons,
                "recommendations": recommendations,
                "additionalFindings": additional_findings
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "schemaVersion": "1.0",
                "transformationId": "isOSVersionCurrent",
                "vendor": "Microsoft Intune",
                "category": "Asset Management"
            }
        }
    }


def parse_major_version(os_name, version_str):
    """Extract major version number from OS version string."""
    if not version_str:
        return None

    # Windows: "10.0.19045.3803" -> major build 19045
    # macOS: "14.2.1" -> major 14
    # iOS: "17.2" -> major 17
    # Android: "14" -> major 14
    parts = version_str.split(".")
    try:
        if os_name and "windows" in os_name.lower():
            # For Windows, the meaningful version is the build number (3rd segment)
            if len(parts) >= 3:
                return int(parts[2])
            return int(parts[0])
        return int(parts[0])
    except (ValueError, IndexError):
        return None


def transform(input):
    """
    Checks that managed devices are running current OS versions.

    Uses a relative approach: finds the highest major version per OS family
    across all devices, then checks if devices are within 2 major versions
    of the highest observed version.

    Returns true if >= 80% of devices are running a current OS version.
    Returns false if too many devices are running outdated OS versions.
    """
    criteriaKey = "isOSVersionCurrent"
    CURRENT_THRESHOLD_PERCENT = 80
    MAX_VERSION_LAG = 2

    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        devices = []
        if isinstance(data, list):
            devices = data
        elif isinstance(data, dict):
            devices = data.get("value", data.get("devices", []))
            if isinstance(devices, dict):
                devices = [devices]

        if not isinstance(devices, list):
            devices = []

        if len(devices) == 0:
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["No managed devices found to evaluate OS versions"],
                recommendations=["Enroll devices into Intune to track OS currency"]
            )

        # Group devices by OS and find highest version per OS
        os_versions = {}
        for device in devices:
            if not isinstance(device, dict):
                continue
            os_name = device.get("operatingSystem", "Unknown")
            os_version = device.get("osVersion", "")
            major = parse_major_version(os_name, os_version)
            if major is not None:
                if os_name not in os_versions:
                    os_versions[os_name] = {"max": major, "devices": []}
                os_versions[os_name]["max"] = max(os_versions[os_name]["max"], major)
                os_versions[os_name]["devices"].append({
                    "version": os_version,
                    "major": major
                })

        # Evaluate currency: device is current if within MAX_VERSION_LAG of max
        current_count = 0
        outdated_count = 0
        unevaluable = 0

        for os_name, info in os_versions.items():
            max_ver = info["max"]
            for dev in info["devices"]:
                if max_ver - dev["major"] <= MAX_VERSION_LAG:
                    current_count += 1
                else:
                    outdated_count += 1

        unevaluable = len(devices) - current_count - outdated_count
        total_evaluable = current_count + outdated_count
        current_pct = (current_count * 100 // total_evaluable) if total_evaluable > 0 else 0

        is_current = current_pct >= CURRENT_THRESHOLD_PERCENT

        if is_current:
            pass_reasons.append(
                "%d%% of devices (%d/%d) are running current OS versions"
                % (current_pct, current_count, total_evaluable)
            )
        else:
            fail_reasons.append(
                "Only %d%% of devices (%d/%d) are running current OS versions "
                "(threshold: %d%%)"
                % (current_pct, current_count, total_evaluable,
                   CURRENT_THRESHOLD_PERCENT)
            )
            recommendations.append(
                "Review and update OS versions on outdated devices. Consider "
                "configuring Windows Update for Business policies and OS "
                "update policies for macOS/iOS to keep devices current."
            )

        if outdated_count > 0:
            additional_findings.append(
                "%d device(s) are running outdated OS versions" % outdated_count
            )
        if unevaluable > 0:
            additional_findings.append(
                "%d device(s) could not be evaluated for OS currency" % unevaluable
            )

        # OS breakdown
        for os_name, info in os_versions.items():
            os_current = sum(1 for d in info["devices"]
                           if info["max"] - d["major"] <= MAX_VERSION_LAG)
            additional_findings.append(
                "%s: %d/%d devices current (latest observed major: %d)"
                % (os_name, os_current, len(info["devices"]), info["max"])
            )

        input_summary = {
            "totalDevices": len(devices),
            "currentDevices": current_count,
            "outdatedDevices": outdated_count,
            "unevaluableDevices": unevaluable,
            "currentPercentage": current_pct
        }

        return create_response(
            result={criteriaKey: is_current},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
