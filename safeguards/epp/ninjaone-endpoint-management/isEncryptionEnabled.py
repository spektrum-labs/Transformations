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


# --- NinjaOne disk-encryption facts (verified against the live "NinjaOne Public API 2.0"
# spec, v2.0.9, 2026-09-03) --------------------------------------------------------------
# * /v2/queries/volumes only returns a bitLockerStatus at all when the request carries
#   include=bl. Without it the field is absent on every record, which this transform used
#   to read as "not encrypted" -> a hard false negative for every customer.
# * bitLockerStatus is an OBJECT, not a string: {conversionStatus, encryptionMethod,
#   protectionStatus, lockStatus, initializedForProtection}. The previous code compared
#   str(the whole dict) against "enabled"/"on"/"encrypted", which can never match.
# * There is no fileVaultStatus field, and no FileVault/encryption property of any kind,
#   anywhere in NinjaOne's public API (0 matches across the whole spec). macOS encryption
#   is therefore NOT answerable from this endpoint. Mac system volumes are reported as
#   unevaluable instead of being silently counted as unencrypted.
# * Windows volumes are identified by driveLetter, NOT by the presence of bitLockerStatus:
#   a Windows box with BitLocker switched off may report no bitLockerStatus object at all,
#   and keying off presence would quietly drop it from the denominator and pass the fleet.
ENCRYPTED_CONVERSION_STATES = ("fully_encrypted",)


def get_bitlocker_status(volume):
    """Return the bitLockerStatus object, or None when the field is absent/not an object."""
    status = volume.get("bitLockerStatus")
    return status if isinstance(status, dict) else None


def is_windows_volume(volume):
    """A drive letter (C:, D:, ...) is only ever reported for Windows volumes."""
    return len((volume.get("driveLetter") or "").strip()) > 0


def is_volume_encrypted(volume):
    """True only for conversionStatus=FULLY_ENCRYPTED. Absent status counts as NOT encrypted."""
    status = get_bitlocker_status(volume)
    if status is None:
        return False
    conversion = str(status.get("conversionStatus") or "").strip().lower()
    return conversion in ENCRYPTED_CONVERSION_STATES


# --- Completeness guard ------------------------------------------------------------------
# NinjaOne DEFECT, measured live 2026-09-03: combining `include=bl` with cursor pagination
# silently DROPS records, and the ones it drops are precisely the Windows volumes carrying
# bitLockerStatus. On a 41-volume tenant: pageSize=1000 -> 41 records / 3 with bitLockerStatus
# (correct); pageSize=20 -> 39 records / 1; pageSize=5 -> 38 records / 0. Without `include`
# pagination is exact at every page size, so this is specific to the include=bl join.
# The definition therefore requests pageSize=10000 to stay on the single-call path. If a
# fleet ever exceeds that, the API's own `cursor.count` (total volumes) will exceed the
# number of records we received, and we refuse to emit a verdict rather than quietly
# grading a subset that is missing exactly the encrypted machines.
def get_expected_total(data):
    """API-reported total volume count, or None when the envelope isn't available."""
    if not isinstance(data, dict):
        return None
    cursor = data.get("cursor")
    if not isinstance(cursor, dict):
        return None
    count = cursor.get("count")
    return count if isinstance(count, int) else None


def is_truncated(data, received):
    expected = get_expected_total(data)
    return expected is not None and expected > received


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

    windows_system_volumes = []
    other_system_volumes = []
    for v in volumes:
        if not isinstance(v, dict):
            continue
        letter = (v.get("driveLetter") or "").strip()
        name = (v.get("name") or "").strip()
        if is_windows_volume(v):
            if letter.upper().startswith("C"):
                windows_system_volumes.append(v)
        elif name == "/":
            other_system_volumes.append(v)

    total = len(windows_system_volumes)
    unevaluable = len(other_system_volumes)
    encrypted_count = 0
    unencrypted_devices = []
    missing_status_devices = []
    sample_statuses = []

    for v in windows_system_volumes:
        if is_volume_encrypted(v):
            encrypted_count = encrypted_count + 1
        else:
            unencrypted_devices.append(v.get("deviceId"))
            if get_bitlocker_status(v) is None:
                missing_status_devices.append(v.get("deviceId"))
        if len(sample_statuses) < 5:
            sample_statuses.append({
                "deviceId": v.get("deviceId"),
                "conversionStatus": (get_bitlocker_status(v) or {}).get("conversionStatus"),
            })

    truncated = is_truncated(data, len(volumes))

    if truncated:
        is_enabled = False
    elif total > 0:
        is_enabled = encrypted_count == total
    else:
        is_enabled = False

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if unevaluable > 0:
        additional_findings.append(
            f"{unevaluable} non-Windows system volume(s) (macOS/Linux) were returned. NinjaOne's "
            "public API exposes no FileVault or generic encryption field, so their encryption state "
            "cannot be read from this endpoint and they are excluded from this result rather than "
            "counted as unencrypted. Verify macOS FileVault by another means (e.g. a NinjaOne custom "
            "field populated by an 'fdesetup status' script)."
        )

    if missing_status_devices:
        additional_findings.append(
            f"{len(missing_status_devices)} Windows system volume(s) returned no bitLockerStatus "
            f"object (device IDs: {missing_status_devices[:10]}). They are counted as not encrypted. "
            "If the getVolumes request omits include=bl, the field is absent for every device and "
            "this result is not trustworthy."
        )

    if truncated:
        fail_reasons.append(
            f"Incomplete data: NinjaOne reported {get_expected_total(data)} volumes but only "
            f"{len(volumes)} were returned. Combining include=bl with cursor pagination drops "
            "records -- and the dropped records are the ones carrying bitLockerStatus -- so no "
            "encryption verdict can be trusted from this response."
        )
        recommendations.append(
            "Raise the getVolumes pageSize so the fleet fits in a single page, or fetch "
            "BitLocker status per device via /v2/device/{id}/volumes."
        )
    elif total == 0:
        fail_reasons.append(
            "No Windows system volumes were found in the getVolumes response, so BitLocker "
            "encryption status could not be confirmed for any device."
            + (f" {unevaluable} non-Windows system volume(s) were present but are not evaluable "
               "through NinjaOne's API." if unevaluable > 0 else "")
        )
        recommendations.append(
            "Confirm Windows devices are enrolled and reporting volume data in NinjaOne. macOS "
            "FileVault status is not exposed by NinjaOne's public API and needs a separate source."
        )
    elif is_enabled:
        pass_reasons.append(
            f"All {total} Windows system volumes report bitLockerStatus.conversionStatus="
            f"FULLY_ENCRYPTED (sample: {sample_statuses})."
        )
    else:
        fail_reasons.append(
            f"Only {encrypted_count} of {total} Windows system volumes report "
            f"conversionStatus=FULLY_ENCRYPTED; affected device IDs include: "
            f"{unencrypted_devices[:10]}."
        )
        recommendations.append(
            "Enable BitLocker on the affected Windows devices and confirm the NinjaOne policy "
            "enforces full-disk encryption."
        )

    result = {
        "isEncryptionEnabled": is_enabled,
        "totalSystemVolumes": total,
        "encryptedSystemVolumes": encrypted_count,
        "unevaluableSystemVolumes": unevaluable,
    }

    input_summary = {
        "totalVolumesReturned": len(volumes) if isinstance(volumes, list) else 0,
        "windowsSystemVolumes": total,
        "encryptedSystemVolumes": encrypted_count,
        "unevaluableSystemVolumes": unevaluable,
        "volumesMissingBitLockerStatus": len(missing_status_devices),
        "reportedTotalVolumes": get_expected_total(data),
        "dataTruncated": truncated,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEncryptionEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
