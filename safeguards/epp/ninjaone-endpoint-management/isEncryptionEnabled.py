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

    if isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
    elif isinstance(data, list):
        results = data
    else:
        results = []

    if not isinstance(results, list):
        results = []

    # Identify system volumes: Windows C: drive or macOS root "/"
    system_volumes = []
    for v in results:
        if not isinstance(v, dict):
            continue
        drive_letter = v.get("driveLetter") or ""
        name = v.get("name") or ""
        if drive_letter == "C:" or name == "/":
            system_volumes.append(v)

    total_system_volumes = len(system_volumes)

    protected_volumes = []
    unprotected_volumes = []
    unknown_volumes = []

    for v in system_volumes:
        bl = v.get("bitLockerStatus")
        if isinstance(bl, dict):
            protection_status = bl.get("protectionStatus") or ""
            if protection_status in ("PROTECTED", "ON", "Protected"):
                protected_volumes.append(v)
            else:
                unprotected_volumes.append(v)
        else:
            # No bitLockerStatus reported - could be macOS FileVault (not exposed
            # by this endpoint) or a device that hasn't reported encryption state.
            unknown_volumes.append(v)

    protected_count = len(protected_volumes)
    unprotected_count = len(unprotected_volumes)
    unknown_count = len(unknown_volumes)

    recommendations = []

    if total_system_volumes == 0:
        is_enabled = False
        fail_reasons = ["No system volumes (C: or /) were found in the volumes report to evaluate encryption status."]
        pass_reasons = []
        recommendations = ["Ensure the NinjaOne volumes query is returning device volume data before evaluating disk encryption."]
    else:
        is_enabled = (protected_count == total_system_volumes) and (protected_count > 0)
        if is_enabled:
            device_ids = [v.get("deviceId") for v in protected_volumes]
            pass_reasons = [
                "All %d system volumes report bitLockerStatus.protectionStatus=PROTECTED (deviceIds sample: %s)."
                % (total_system_volumes, device_ids[:5])
            ]
            fail_reasons = []
        else:
            pass_reasons = []
            fail_reasons = []
            if unprotected_count > 0:
                dev_ids = [v.get("deviceId") for v in unprotected_volumes]
                fail_reasons.append(
                    "%d of %d system volumes report bitLockerStatus.protectionStatus not PROTECTED (deviceIds sample: %s)."
                    % (unprotected_count, total_system_volumes, dev_ids[:5])
                )
            if unknown_count > 0:
                dev_ids = [v.get("deviceId") for v in unknown_volumes]
                fail_reasons.append(
                    "%d of %d system volumes have no bitLockerStatus field reported, so encryption state cannot be confirmed (deviceIds sample: %s)."
                    % (unknown_count, total_system_volumes, dev_ids[:5])
                )
            recommendations.append(
                "Enable BitLocker (Windows) or FileVault (macOS) on the system volume for devices lacking a PROTECTED status, and confirm devices are reporting encryption state to NinjaOne."
            )

    result = {
        "isEncryptionEnabled": is_enabled,
        "totalSystemVolumes": total_system_volumes,
        "protectedVolumes": protected_count,
        "unprotectedVolumes": unprotected_count,
        "unknownEncryptionStatusVolumes": unknown_count,
    }

    input_summary = {
        "totalVolumeRecords": len(results),
        "totalSystemVolumes": total_system_volumes,
        "protectedVolumes": protected_count,
        "unprotectedVolumes": unprotected_count,
        "unknownEncryptionStatusVolumes": unknown_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isEncryptionEnabled", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )
