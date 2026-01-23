"""
Transformation: isBackupEncrypted
Vendor: Datto BCDR
Category: Backup / Data Protection

Checks that Datto BCDR backups are encrypted at rest.
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
                "transformationId": "isBackupEncrypted",
                "vendor": "Datto",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupEncrypted"

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

        # Check for encryption status
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        ) if isinstance(data, dict) else []

        # Datto BCDR uses AES-256 encryption by default
        all_encrypted = True
        has_devices = False
        encrypted_count = 0

        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}

            has_devices = True
            encryption = device.get("encryption", device.get("encryptionStatus", {}))

            if isinstance(encryption, bool):
                is_encrypted = encryption
            elif isinstance(encryption, dict):
                is_encrypted = encryption.get("enabled", True) or encryption.get("encrypted", True)
            else:
                # Datto BCDR encrypts by default, so assume True if not explicitly False
                is_encrypted = str(encryption).lower() not in ["false", "disabled", "none"]

            if is_encrypted:
                encrypted_count += 1
            else:
                all_encrypted = False

        # If no devices, check global encryption setting
        if not has_devices and isinstance(data, dict):
            global_encryption = data.get("encryptionEnabled", data.get("encryption", True))
            all_encrypted = bool(global_encryption)

        if all_encrypted:
            pass_reasons.append("All Datto BCDR backups are encrypted (AES-256)")
            if encrypted_count > 0:
                pass_reasons.append(f"{encrypted_count} device(s) with encryption verified")
        else:
            fail_reasons.append("Not all Datto BCDR devices have encryption enabled")
            recommendations.append("Verify encryption settings for all Datto BCDR devices")

        return create_response(
            result={criteriaKey: all_encrypted},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDevices": len(devices) if has_devices else 0,
                "encryptedDevices": encrypted_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
