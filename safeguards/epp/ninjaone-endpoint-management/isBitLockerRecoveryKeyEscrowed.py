import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


ENCRYPTED_VALUES = ("enabled", "on", "encrypted", "true", "yes")
RECOVERY_KEY_FIELDS = [
    "recoveryKey",
    "recoveryPassword",
    "recoveryKeyId",
    "keyEscrowed",
    "escrowed",
    "bitLockerRecoveryKey",
    "fileVaultRecoveryKey",
    "keyProtectorType",
    "recoveryKeyEscrowed",
]


def is_truthy_value(value):
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return len(value.strip()) > 0
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return False


def is_encrypted_volume(volume):
    for key in ("bitLockerStatus", "fileVaultStatus", "encryptionStatus"):
        val = volume.get(key)
        if isinstance(val, str) and val.strip().lower() in ENCRYPTED_VALUES:
            return True
        if isinstance(val, bool) and val:
            return True
    return False


def has_recovery_key(volume):
    for key in RECOVERY_KEY_FIELDS:
        if key in volume and is_truthy_value(volume.get(key)):
            return True
    return False


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        volumes = data
    elif isinstance(data, dict):
        volumes = data.get("results") or data.get("data") or []
        if not isinstance(volumes, list):
            volumes = []
    else:
        volumes = []

    total_volumes = len(volumes)
    encrypted_count = 0
    escrowed_count = 0
    sample_escrowed_names = []
    sample_missing_names = []

    for vol in volumes:
        if not isinstance(vol, dict):
            continue
        if is_encrypted_volume(vol):
            encrypted_count = encrypted_count + 1
            if has_recovery_key(vol):
                escrowed_count = escrowed_count + 1
                if len(sample_escrowed_names) < 5:
                    sample_escrowed_names.append(vol.get("name") or vol.get("deviceId"))
            else:
                if len(sample_missing_names) < 5:
                    sample_missing_names.append(vol.get("name") or vol.get("deviceId"))

    input_summary = {
        "totalVolumes": total_volumes,
        "encryptedVolumes": encrypted_count,
        "escrowedVolumes": escrowed_count,
    }

    if encrypted_count == 0:
        is_escrowed = False
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_volumes} volumes returned by getVolumes report an "
            "encryption status (bitLockerStatus/fileVaultStatus) of Enabled/On/Encrypted, "
            "and no recovery-key fields were present, so no encrypted volume with an escrowed "
            "recovery key could be confirmed."
        ]
        recommendations = [
            "Confirm BitLocker/FileVault is enabled on managed endpoints and that the volumes "
            "report an encryption status through the NinjaOne agent so recovery-key escrow can "
            "be verified."
        ]
    else:
        is_escrowed = escrowed_count == encrypted_count
        if is_escrowed:
            pass_reasons = [
                f"All {encrypted_count} encrypted volumes (out of {total_volumes} total volumes) "
                f"carry a non-empty recovery-key field (e.g. {sample_escrowed_names}), confirming "
                "the BitLocker/FileVault recovery key is captured and escrowed centrally."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                f"{escrowed_count} of {encrypted_count} encrypted volumes have a recovery-key "
                f"field populated; the remaining {encrypted_count - escrowed_count} encrypted "
                f"volumes (e.g. {sample_missing_names}) show no recovery-key value, meaning their "
                "keys are not confirmed escrowed."
            ]
            recommendations = [
                "Investigate the encrypted volumes missing a recovery-key value and re-enroll or "
                "trigger a key backup so BitLocker/FileVault recovery keys are escrowed centrally."
            ]

    result = {
        "isBitLockerRecoveryKeyEscrowed": is_escrowed,
        "totalVolumes": total_volumes,
        "encryptedVolumes": encrypted_count,
        "escrowedVolumes": escrowed_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isBitLockerRecoveryKeyEscrowed",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
