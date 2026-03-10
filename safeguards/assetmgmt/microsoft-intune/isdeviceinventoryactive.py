import json
from datetime import datetime


def extract_input(input_data):
    """
    Unwraps nested API response wrappers to extract the actual data payload.
    Supports both new format (data + validation) and legacy wrapper formats.
    """
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
    """
    Builds a standardized response envelope for PostureStream consumption.
    """
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
                "transformationId": "isDeviceInventoryActive",
                "vendor": "Microsoft Intune",
                "category": "Asset Management"
            }
        }
    }


def transform(input):
    """
    Checks that Intune has managed devices enrolled and reporting.

    Returns true if at least one managed device exists in the inventory.
    Returns false if no devices are enrolled or data is unavailable.
    """
    criteriaKey = "isDeviceInventoryActive"

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

        devices = []
        if isinstance(data, list):
            devices = data
        elif isinstance(data, dict):
            devices = data.get("value", data.get("devices", []))
            if isinstance(devices, dict):
                devices = [devices]

        if not isinstance(devices, list):
            devices = []

        device_count = len(devices)
        is_active = device_count > 0

        if is_active:
            os_breakdown = {}
            for device in devices:
                if isinstance(device, dict):
                    os = device.get("operatingSystem", "Unknown")
                    os_breakdown[os] = os_breakdown.get(os, 0) + 1

            pass_reasons.append(
                "%d managed device(s) enrolled in Intune" % device_count
            )
            if os_breakdown:
                breakdown_str = ", ".join(
                    "%s: %d" % (k, v) for k, v in sorted(os_breakdown.items())
                )
                pass_reasons.append("OS breakdown: %s" % breakdown_str)
        else:
            fail_reasons.append(
                "No managed devices found in Intune device inventory"
            )
            recommendations.append(
                "Enroll devices into Intune via Autopilot, manual enrollment, "
                "or co-management with Configuration Manager"
            )

        input_summary = {
            "deviceCount": device_count
        }

        return create_response(
            result={criteriaKey: is_active},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
