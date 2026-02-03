"""
Transformation: isBackupEnabledForCriticalSystems
Vendor: Datto BCDR
Category: Backup / Data Protection

Checks that Datto BCDR backups are enabled for critical systems (servers).
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
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
                "transformationId": "isBackupEnabledForCriticalSystems",
                "vendor": "Datto",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupEnabledForCriticalSystems"

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

        # Check for critical system protection
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        ) if isinstance(data, dict) else []

        critical_protected = False
        critical_count = 0
        protected_critical_count = 0

        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}

            # Determine if device is critical (server)
            device_type = (
                device.get("type", "") or
                device.get("deviceType", "") or
                device.get("osType", "")
            )
            if isinstance(device_type, str):
                device_type = device_type.lower()
            else:
                device_type = ""

            is_critical = (
                device.get("isCritical", False) or
                device.get("criticalSystem", False) or
                device_type in ["server", "windows_server", "linux_server", "virtual_server"]
            )

            if is_critical:
                critical_count += 1

                # Check if backup is enabled for this critical system
                backup_enabled = (
                    device.get("backupEnabled", False) or
                    device.get("isProtected", False) or
                    device.get("lastBackup") is not None or
                    device.get("status", "").lower() in ["protected", "active", "ok"]
                )

                if backup_enabled:
                    critical_protected = True
                    protected_critical_count += 1

        if critical_protected:
            pass_reasons.append(f"Backup enabled for critical systems: {protected_critical_count}/{critical_count} servers protected")
        else:
            if critical_count > 0:
                fail_reasons.append(f"No backups enabled for {critical_count} critical systems")
            else:
                fail_reasons.append("No critical systems (servers) found in Datto BCDR")
            recommendations.append("Enable Datto BCDR backup for all critical servers")

        return create_response(
            result={criteriaKey: critical_protected},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDevices": len(devices),
                "criticalSystems": critical_count,
                "protectedCriticalSystems": protected_critical_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
