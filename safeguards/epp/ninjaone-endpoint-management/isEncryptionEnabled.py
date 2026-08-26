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

    system_volumes = []
    for v in volumes:
        if not isinstance(v, dict):
            continue
        letter = (v.get("driveLetter") or "").strip()
        name = (v.get("name") or "").strip()
        is_system = letter == "C:" or name == "/"
        if is_system:
            system_volumes.append(v)

    total = len(system_volumes)
    encrypted_count = 0
    unencrypted_devices = []
    sample_statuses = []

    for v in system_volumes:
        bl = v.get("bitLockerStatus")
        fv = v.get("fileVaultStatus")
        status = bl if bl is not None else fv
        is_enc = False
        if status is not None:
            s = str(status).strip().lower()
            if s in ("enabled", "on", "encrypted", "protected", "fullyencrypted"):
                is_enc = True
        if is_enc:
            encrypted_count = encrypted_count + 1
        else:
            unencrypted_devices.append(v.get("deviceId"))
        if len(sample_statuses) < 5:
            sample_statuses.append({"deviceId": v.get("deviceId"), "status": status})

    if total > 0:
        is_enabled = encrypted_count == total
    else:
        is_enabled = False

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append(
            "No system volumes (Windows C: or macOS root '/') were found in the getVolumes response, "
            "so disk encryption status could not be confirmed for any device."
        )
        recommendations.append(
            "Verify that the NinjaOne agent is reporting volume data (bitLockerStatus/fileVaultStatus) "
            "for enrolled devices."
        )
    elif is_enabled:
        pass_reasons.append(
            f"All {total} system volumes report an encrypted bitLockerStatus/fileVaultStatus "
            f"(e.g. sample: {sample_statuses})."
        )
    else:
        fail_reasons.append(
            f"Only {encrypted_count} of {total} system volumes report an encrypted status; "
            f"unencrypted device IDs include: {unencrypted_devices[:10]}."
        )
        recommendations.append(
            "Enable BitLocker on Windows devices and FileVault on macOS devices for the system volume, "
            "and confirm the NinjaOne policy enforces full-disk encryption."
        )

    result = {
        "isEncryptionEnabled": is_enabled,
        "totalSystemVolumes": total,
        "encryptedSystemVolumes": encrypted_count,
    }

    input_summary = {
        "totalVolumesReturned": len(volumes) if isinstance(volumes, list) else 0,
        "systemVolumesIdentified": total,
        "encryptedSystemVolumes": encrypted_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEncryptionEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
