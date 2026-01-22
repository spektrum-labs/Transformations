"""
Transformation: isBackupEnabled
Vendor: Datto BCDR
Category: Backup / Data Protection

Evaluates whether backups are enabled on Datto BCDR devices.
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
                "transformationId": "isBackupEnabled",
                "vendor": "Datto",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupEnabled"

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

        # Check for devices with backups
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        ) if isinstance(data, dict) else []

        is_enabled = False
        protected_count = 0

        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}

            backup_enabled = (
                device.get("backupEnabled", False) or
                device.get("isProtected", False) or
                device.get("lastBackup") is not None or
                device.get("status", "").lower() in ["protected", "active", "ok"]
            )
            if backup_enabled:
                is_enabled = True
                protected_count += 1
            else:
                backups = device.get("backups", [])
                if backups and len(backups) > 0:
                    is_enabled = True
                    protected_count += 1

        if is_enabled:
            pass_reasons.append(f"Backup is enabled with {protected_count} protected device(s)")
        else:
            fail_reasons.append("No Datto BCDR devices with backup enabled found")
            recommendations.append("Enable backup protection for Datto BCDR devices")

        return create_response(
            result={criteriaKey: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDevices": len(devices),
                "protectedDevices": protected_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
