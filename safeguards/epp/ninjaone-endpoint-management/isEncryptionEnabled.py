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

    total_volumes = len(volumes)

    # Identify system-volume-like entries: root ("/") or Windows drive letters (C:)
    system_like = []
    for v in volumes:
        if not isinstance(v, dict):
            continue
        name = v.get("name") or ""
        drive_letter = v.get("driveLetter") or ""
        if name == "/" or drive_letter.upper() == "C:" or name.upper() == "C:":
            system_like.append(v)

    # If we couldn't identify system volumes specifically, fall back to all volumes
    scope = system_like if system_like else volumes

    with_status = [v for v in scope if isinstance(v, dict) and v.get("bitLockerStatus")]
    enabled = [v for v in with_status if str(v.get("bitLockerStatus")).upper() == "ENABLED"]
    disabled = [v for v in with_status if str(v.get("bitLockerStatus")).upper() != "ENABLED"]

    fail_reasons = []
    pass_reasons = []
    recommendations = []

    if len(with_status) == 0:
        # No bitLockerStatus field present at all in the captured payload/scope.
        is_enabled = False
        fail_reasons.append(
            "None of the %d system-volume records inspected (of %d total volume records returned by "
            "getDiskVolumesReport) carry a bitLockerStatus field. This field is only populated when the "
            "endpoint is queried with include=bl and the underlying devices are Windows systems; this "
            "tenant's captured volume records show no bitLockerStatus values at all." % (len(scope), total_volumes)
        )
        recommendations.append(
            "Confirm the volumes query includes the bl (BitLocker) status parameter and that Windows "
            "endpoints are reporting; for macOS systems, confirm FileVault status is being retrieved through "
            "an equivalent field before treating this criterion as failing outright."
        )
    else:
        is_enabled = len(disabled) == 0 and len(enabled) > 0
        if is_enabled:
            pass_reasons.append(
                "All %d system volume records with a reported bitLockerStatus show ENABLED (sample deviceIds: %s)."
                % (len(with_status), [v.get("deviceId") for v in enabled][:5])
            )
        else:
            fail_reasons.append(
                "%d of %d system volume records with a reported bitLockerStatus are not ENABLED (sample deviceIds: %s)."
                % (len(disabled), len(with_status), [v.get("deviceId") for v in disabled][:5])
            )
            recommendations.append(
                "Enable BitLocker/FileVault full-disk encryption on the devices whose system volumes report a "
                "non-ENABLED bitLockerStatus."
            )

    input_summary = {
        "totalVolumeRecords": total_volumes,
        "systemVolumeRecordsInspected": len(scope),
        "recordsWithBitLockerStatus": len(with_status),
        "enabledCount": len(enabled),
        "disabledCount": len(disabled),
    }

    result = {
        "isEncryptionEnabled": is_enabled,
        "totalVolumes": total_volumes,
        "volumesWithStatus": len(with_status),
        "enabledVolumes": len(enabled),
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
