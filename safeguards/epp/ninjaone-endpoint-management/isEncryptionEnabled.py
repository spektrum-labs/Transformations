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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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


ENCRYPTED_STATES = ["encrypted", "fullyencrypted", "on", "protected", "protectionon"]
UNENCRYPTED_STATES = ["decrypted", "off", "unencrypted", "notencrypted", "protectionoff", "unprotected"]


def is_system_volume(volume):
    drive_letter = (volume.get("driveLetter") or "").strip().lower()
    name = (volume.get("name") or "").strip().lower()
    if drive_letter == "c:":
        return True
    if name in ("/", "c:"):
        return True
    return False


def classify_status(value):
    if not isinstance(value, str) or not value:
        return "unknown"
    normalized = value.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
    if normalized in ENCRYPTED_STATES:
        return "encrypted"
    if normalized in UNENCRYPTED_STATES:
        return "unencrypted"
    return "unknown"


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}
    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    system_volumes = [v for v in results if isinstance(v, dict) and is_system_volume(v)]

    total_system_volumes = len(system_volumes)
    encrypted_count = 0
    unencrypted_count = 0
    unknown_count = 0
    sample_findings = []

    for vol in system_volumes:
        bitlocker = vol.get("bitLockerStatus")
        filevault = vol.get("fileVaultStatus")
        status_value = bitlocker if bitlocker is not None else filevault
        classification = classify_status(status_value)
        if classification == "encrypted":
            encrypted_count = encrypted_count + 1
        elif classification == "unencrypted":
            unencrypted_count = unencrypted_count + 1
        else:
            unknown_count = unknown_count + 1
        if len(sample_findings) < 5:
            device_id = vol.get("deviceId")
            vol_name = vol.get("name")
            sample_findings.append(
                f"deviceId={device_id} volume={vol_name} status={status_value} classified={classification}"
            )

    is_encryption_enabled = False
    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_system_volumes == 0:
        fail_reasons.append(
            "No system volumes (C: or /) were found in the getVolumes report, so encryption status could not be determined."
        )
        recommendations.append(
            "Verify NinjaOne is reporting disk volume data for endpoints and that the queries/volumes report includes system volumes."
        )
    elif unknown_count == total_system_volumes:
        fail_reasons.append(
            f"None of the {total_system_volumes} system volume(s) inspected exposed a recognizable bitLockerStatus or fileVaultStatus value (e.g. sample: {sample_findings[:1]}). Encryption state cannot be confirmed from this response."
        )
        recommendations.append(
            "Confirm the queries/volumes endpoint returns bitLockerStatus (Windows) or fileVaultStatus (macOS) fields for this tenant; without them full-disk encryption state cannot be verified."
        )
    elif unencrypted_count > 0:
        is_encryption_enabled = False
        fail_reasons.append(
            f"{unencrypted_count} of {total_system_volumes} system volume(s) report an unencrypted status (samples: {sample_findings}). Full-disk encryption is not complete across the fleet."
        )
        recommendations.append(
            "Enable BitLocker (Windows) or FileVault (macOS) on all endpoints reporting an unencrypted system volume."
        )
    elif encrypted_count == total_system_volumes:
        is_encryption_enabled = True
        pass_reasons.append(
            f"All {total_system_volumes} system volume(s) report an encrypted bitLockerStatus/fileVaultStatus value (samples: {sample_findings})."
        )
    else:
        fail_reasons.append(
            f"{encrypted_count} of {total_system_volumes} system volume(s) confirmed encrypted, but {unknown_count} report an unrecognized status (samples: {sample_findings}); full-disk encryption cannot be confirmed complete."
        )
        recommendations.append(
            "Investigate system volumes with unrecognized encryption status values to confirm BitLocker/FileVault state."
        )

    result = {
        "isEncryptionEnabled": is_encryption_enabled,
        "totalSystemVolumes": total_system_volumes,
        "encryptedSystemVolumes": encrypted_count,
        "unencryptedSystemVolumes": unencrypted_count,
        "unknownStatusSystemVolumes": unknown_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalVolumesInResponse": len(results),
            "systemVolumesInspected": total_system_volumes,
        },
        metadata={
            "transformationId": "isEncryptionEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
