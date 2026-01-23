"""
Transformation: isBackupTypesScheduled
Vendor: Datto BCDR
Category: Backup / Data Protection

Checks if Datto BCDR backup schedules are configured.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupTypesScheduled",
                "vendor": "Datto",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupTypesScheduled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

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

        # Check for backup schedules
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        ) if isinstance(data, dict) else []

        scheduled = False
        scheduled_count = 0

        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}

            # Check schedule configuration
            schedule = device.get("schedule", device.get("backupSchedule", {}))
            if isinstance(schedule, dict):
                if schedule.get("enabled", False) or schedule.get("frequency"):
                    scheduled = True
                    scheduled_count += 1
                    continue
            elif schedule:
                scheduled = True
                scheduled_count += 1
                continue

            # Check for scheduled backup flag
            if device.get("scheduledBackup", False):
                scheduled = True
                scheduled_count += 1
                continue

            # Check for backup interval
            interval = device.get("backupInterval", device.get("interval", 0))
            if interval and interval > 0:
                scheduled = True
                scheduled_count += 1
                continue

            isPaused = device.get("isPaused", False)
            if not isPaused:
                isArchived = device.get("isArchived", False)
                if not isArchived:
                    backups = device.get("backups", [])
                    if backups and len(backups) > 0:
                        scheduled = True
                        scheduled_count += 1

        if scheduled:
            pass_reasons.append(f"Backup schedules configured for {scheduled_count} device(s)")
        else:
            fail_reasons.append("No Datto BCDR backup schedules configured")
            recommendations.append("Configure backup schedules for all Datto BCDR devices")

        return create_response(
            result={criteriaKey: scheduled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDevices": len(devices),
                "scheduledDevices": scheduled_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
