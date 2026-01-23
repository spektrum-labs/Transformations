"""
Transformation: isBackupImmutable
Vendor: AWS
Category: Backups / Security

Checks that Backup Vault Lock is active (i.e. immutable) by parsing the
JSON response from the GetBackupVaultLockConfiguration REST API.
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
                "transformationId": "isBackupImmutable",
                "vendor": "AWS",
                "category": "Backups"
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

        # Grab the lock configuration block
        lock_conf = data.get("BackupVaultLockConfiguration", {}) if isinstance(data, dict) else {}
        lock_state = lock_conf.get("LockState", "").upper() if lock_conf else ""
        is_immutable = (lock_state == "LOCKED")

        vault_name = data.get("BackupVaultName", "unknown") if isinstance(data, dict) else "unknown"

        if is_immutable:
            pass_reasons.append(f"Backup vault '{vault_name}' is locked and immutable")
        else:
            if lock_state:
                fail_reasons.append(f"Backup vault '{vault_name}' lock state is '{lock_state}' (not LOCKED)")
            else:
                fail_reasons.append(f"Backup vault '{vault_name}' has no lock configuration")
            recommendations.append("Enable Backup Vault Lock to make backups immutable")

        return create_response(
            result={criteriaKey: is_immutable},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "vaultName": vault_name,
                "lockState": lock_state,
                "hasLockConfiguration": bool(lock_conf)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
