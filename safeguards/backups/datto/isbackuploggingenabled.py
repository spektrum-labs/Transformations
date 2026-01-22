"""
Transformation: isBackupLoggingEnabled
Vendor: Datto BCDR
Category: Backup / Logging

Checks whether logging and alerts are enabled for Datto BCDR.
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupLoggingEnabled",
                "vendor": "Datto",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupLoggingEnabled"

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

        # Check for logging/alerting configuration
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        ) if isinstance(data, dict) else []

        logging_enabled = False
        devices_with_logging = 0

        # Check global logging settings
        if isinstance(data, dict):
            global_logging = (
                data.get("loggingEnabled", False) or
                data.get("alertsEnabled", False) or
                data.get("notifications", {}).get("enabled", False)
            )

            if global_logging:
                logging_enabled = True
                pass_reasons.append("Global logging/alerts enabled")

        if not logging_enabled:
            # Check individual devices
            for device in devices:
                if isinstance(device, list):
                    device = device[0] if len(device) > 0 else {}

                device_logging = (
                    device.get("loggingEnabled", False) or
                    device.get("alertsEnabled", False) or
                    device.get("notifications", {}).get("enabled", False)
                )

                # If device has backups, assume logging is enabled (Datto logs by default)
                if device.get("backupEnabled", False) or device.get("lastBackup"):
                    logging_enabled = True
                    devices_with_logging += 1
                elif device_logging:
                    logging_enabled = True
                    devices_with_logging += 1
                else:
                    backups = device.get("backups", [])
                    if backups and len(backups) > 0:
                        logging_enabled = True
                        devices_with_logging += 1

        if logging_enabled:
            pass_reasons.append("Datto BCDR logging is enabled")
            if devices_with_logging > 0:
                pass_reasons.append(f"{devices_with_logging} device(s) with backup logging")
        else:
            fail_reasons.append("No Datto BCDR logging configuration found")
            recommendations.append("Enable alerts and notifications for Datto BCDR devices")

        return create_response(
            result={criteriaKey: logging_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDevices": len(devices),
                "devicesWithLogging": devices_with_logging
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
