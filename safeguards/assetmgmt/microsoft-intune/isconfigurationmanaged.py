import json
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
                "transformationId": "isConfigurationManaged",
                "vendor": "Microsoft Intune",
                "category": "Asset Management"
            }
        }
    }


def transform(input):
    """
    Checks that enrolled devices have configuration profiles deployed and enforced.

    This workflow receives merged data from getDeviceConfigurations and
    getManagedDevices. Returns true if:
    1. Config profiles exist (configuration is defined), AND
    2. Managed devices exist and have configurationManagerClientEnabledFeatures
       or are in a managed state (configuration is being applied)

    Returns false if no config profiles exist or no devices are managed.
    """
    criteriaKey = "isConfigurationManaged"

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

        # Extract configs and devices from merged data
        configs = []
        devices = []

        if isinstance(data, dict):
            # Merged workflow: look for both configurations and devices
            configs = data.get("configurations", data.get("value", []))
            devices = data.get("devices", [])

            # If data has a single "value" array, try to distinguish by content
            if not devices and isinstance(configs, list) and len(configs) > 0:
                # Check if items look like devices vs configs
                first = configs[0] if configs else {}
                if isinstance(first, dict) and "operatingSystem" in first:
                    devices = configs
                    configs = []
        elif isinstance(data, list):
            # Single array — check what type of objects
            if len(data) > 0 and isinstance(data[0], dict):
                if "operatingSystem" in data[0]:
                    devices = data
                else:
                    configs = data

        if not isinstance(configs, list):
            configs = []
        if not isinstance(devices, list):
            devices = []

        has_configs = len(configs) > 0
        has_devices = len(devices) > 0

        # Check if devices are being managed (not just enrolled)
        managed_device_count = 0
        for device in devices:
            if not isinstance(device, dict):
                continue
            management_agent = device.get("managementAgent", "")
            if management_agent in ("mdm", "easMdm", "configurationManagerClientMdm",
                                     "configurationManagerClient"):
                managed_device_count += 1

        is_managed = has_configs and (has_devices and managed_device_count > 0)

        if is_managed:
            pass_reasons.append(
                "%d configuration profile(s) deployed to %d managed device(s)"
                % (len(configs), managed_device_count)
            )
        else:
            if not has_configs:
                fail_reasons.append("No configuration profiles found in Intune")
                recommendations.append(
                    "Create device configuration profiles to manage device "
                    "settings and security baselines"
                )
            if not has_devices:
                fail_reasons.append("No managed devices found to receive configurations")
                recommendations.append(
                    "Enroll devices into Intune management"
                )
            elif managed_device_count == 0:
                fail_reasons.append(
                    "Devices exist but none are under active MDM management"
                )
                recommendations.append(
                    "Ensure devices are enrolled via MDM (not just registered) "
                    "to receive configuration profiles"
                )

        if has_devices and managed_device_count < len(devices):
            unmanaged = len(devices) - managed_device_count
            additional_findings.append(
                "%d device(s) are enrolled but not under active MDM management"
                % unmanaged
            )

        input_summary = {
            "configProfileCount": len(configs),
            "totalDevices": len(devices),
            "managedDevices": managed_device_count
        }

        return create_response(
            result={criteriaKey: is_managed},
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
