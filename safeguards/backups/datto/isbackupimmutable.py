"""
Transformation: isBackupImmutable
Vendor: Datto BCDR
Category: Backup / Data Protection

Checks that Datto BCDR backups are immutable (Cloud Deletion Defense / Ransomware Shield).
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupImmutable",
                "vendor": "Datto",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupImmutable"

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

        # Check for immutability/ransomware shield status
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        ) if isinstance(data, dict) else []

        is_immutable = False
        immutable_count = 0

        # Check global immutability settings first
        if isinstance(data, dict):
            global_immutable = (
                data.get("cloudDeletionDefense", False) or
                data.get("ransomwareShield", False) or
                data.get("immutableBackup", False) or
                data.get("retentionLock", False)
            )

            if global_immutable:
                is_immutable = True
                pass_reasons.append("Global immutability/ransomware shield enabled")

        if not is_immutable:
            # Check individual devices
            for device in devices:
                if isinstance(device, list):
                    device = device[0] if len(device) > 0 else {}

                device_immutable = (
                    device.get("immutableBackup", False) or
                    device.get("ransomwareShield", False) or
                    device.get("cloudDeletionDefense", False) or
                    device.get("retentionLock", False)
                )
                if device_immutable:
                    is_immutable = True
                    immutable_count += 1

        if is_immutable:
            if immutable_count > 0:
                pass_reasons.append(f"{immutable_count} device(s) with immutable backup enabled")
            pass_reasons.append("Datto Cloud Deletion Defense / Ransomware Shield active")
        else:
            fail_reasons.append("No immutable backup protection found")
            recommendations.append("Enable Datto Cloud Deletion Defense or Ransomware Shield")

        return create_response(
            result={criteriaKey: is_immutable},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDevices": len(devices),
                "immutableDevices": immutable_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
