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


# --- What NinjaOne can and cannot tell us about recovery-key escrow ---------------------
# Verified against the live "NinjaOne Public API 2.0" spec (v2.0.9, 2026-09-03):
# * The fields this transform used to look for (recoveryKey, recoveryPassword, recoveryKeyId,
#   keyEscrowed, escrowed, bitLockerRecoveryKey, fileVaultRecoveryKey, keyProtectorType,
#   recoveryKeyEscrowed) do not exist. "recover" and "escrow" have ZERO matches across the
#   entire API surface. NinjaOne stores recovery keys and shows them in its UI, but never
#   exposes them, or an escrow flag, through the public API.
# * The closest available signal is bitLockerStatus.protectionStatus, spec'd as "indicates
#   whether the volume and its encryption key (if any) are secured". PROTECTED means
#   BitLocker protection is active with key protectors in place. That is a proxy for
#   "the key is secured", NOT proof the key is escrowed centrally -- surfaced in
#   additionalFindings so nobody reads more into it than it says.
# * bitLockerStatus is only present when the request carries include=bl, and it is an
#   OBJECT, not a string. It exists for Windows only; there is no FileVault equivalent.
ENCRYPTED_CONVERSION_STATES = ("fully_encrypted",)
PROTECTED_STATES = ("protected",)


def get_bitlocker_status(volume):
    """Return the bitLockerStatus object, or None when the field is absent/not an object."""
    status = volume.get("bitLockerStatus")
    return status if isinstance(status, dict) else None


def is_windows_volume(volume):
    """A drive letter (C:, D:, ...) is only ever reported for Windows volumes."""
    return len((volume.get("driveLetter") or "").strip()) > 0


def is_volume_encrypted(volume):
    status = get_bitlocker_status(volume)
    if status is None:
        return False
    return str(status.get("conversionStatus") or "").strip().lower() in ENCRYPTED_CONVERSION_STATES


def describe_volume(volume):
    """Label a volume so a reader can find the machine: 'C: (device 15)'."""
    name = volume.get("name") or volume.get("driveLetter") or "?"
    return f"{name} (device {volume.get('deviceId')})"


def is_key_secured(volume):
    status = get_bitlocker_status(volume)
    if status is None:
        return False
    return str(status.get("protectionStatus") or "").strip().lower() in PROTECTED_STATES


# --- Completeness guard ------------------------------------------------------------------
# NinjaOne DEFECT, measured live 2026-09-03: `include=bl` combined with cursor pagination
# silently drops records, and the dropped records are exactly the Windows volumes carrying
# bitLockerStatus (41-volume tenant: pageSize=1000 -> 3 bitLocker records; pageSize=5 -> 0).
# Without `include` pagination is exact. The definition requests pageSize=10000 to stay on
# the single-call path; if a fleet exceeds it, `cursor.count` exceeds what we received and
# we refuse to emit a verdict rather than grade a subset missing the encrypted machines.
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

    windows_volumes = []
    non_windows_count = 0
    for v in volumes:
        if not isinstance(v, dict):
            continue
        if is_windows_volume(v):
            windows_volumes.append(v)
        else:
            non_windows_count = non_windows_count + 1

    total_volumes = len(windows_volumes)
    encrypted_count = 0
    escrowed_count = 0
    sample_escrowed_names = []
    sample_missing_names = []

    for vol in windows_volumes:
        if is_volume_encrypted(vol):
            encrypted_count = encrypted_count + 1
            if is_key_secured(vol):
                escrowed_count = escrowed_count + 1
                if len(sample_escrowed_names) < 5:
                    sample_escrowed_names.append(describe_volume(vol))
            else:
                if len(sample_missing_names) < 5:
                    sample_missing_names.append(describe_volume(vol))

    truncated = is_truncated(data, len(volumes))

    input_summary = {
        "totalVolumesReturned": len(volumes) if isinstance(volumes, list) else 0,
        "windowsVolumesEvaluated": total_volumes,
        "encryptedVolumes": encrypted_count,
        "escrowedVolumes": escrowed_count,
        "reportedTotalVolumes": get_expected_total(data),
        "dataTruncated": truncated,
    }

    additional_findings = [
        "NinjaOne's public API exposes neither the recovery key nor an escrow flag, so this "
        "result uses bitLockerStatus.protectionStatus=PROTECTED ('the volume and its encryption "
        "key are secured') as a proxy for key escrow. It confirms BitLocker key protectors are "
        "in place, not that the key is held centrally. macOS (FileVault) volumes have no "
        "equivalent field at all and are excluded."
    ]
    if non_windows_count > 0:
        additional_findings.append(
            f"{non_windows_count} non-Windows volume(s) were returned and excluded: NinjaOne "
            "reports no encryption or recovery-key data for them."
        )

    if truncated:
        is_escrowed = False
        pass_reasons = []
        fail_reasons = [
            f"Incomplete data: NinjaOne reported {get_expected_total(data)} volumes but only "
            f"{len(volumes)} were returned. Combining include=bl with cursor pagination drops "
            "records -- and the dropped records are the ones carrying bitLockerStatus -- so "
            "recovery-key protection cannot be assessed from this response."
        ]
        recommendations = [
            "Raise the getVolumes pageSize so the fleet fits in a single page, or fetch "
            "BitLocker status per device via /v2/device/{id}/volumes."
        ]
    elif encrypted_count == 0:
        is_escrowed = False
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_volumes} Windows volumes returned by getVolumes report "
            "bitLockerStatus.conversionStatus=FULLY_ENCRYPTED, so no encrypted volume with a "
            "secured recovery key could be confirmed."
        ]
        recommendations = [
            "Confirm BitLocker is enabled on managed Windows endpoints, and that the getVolumes "
            "request carries include=bl -- without it NinjaOne omits bitLockerStatus entirely."
        ]
    else:
        is_escrowed = escrowed_count == encrypted_count
        if is_escrowed:
            pass_reasons = [
                f"All {encrypted_count} encrypted Windows volumes (of {total_volumes} evaluated) "
                f"report bitLockerStatus.protectionStatus=PROTECTED (e.g. {sample_escrowed_names}), "
                "indicating the volume's encryption key is secured."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                f"{escrowed_count} of {encrypted_count} encrypted Windows volumes report "
                f"protectionStatus=PROTECTED; the remaining {encrypted_count - escrowed_count} "
                f"(e.g. {sample_missing_names}) do not, so their encryption key is not confirmed "
                "secured."
            ]
            recommendations = [
                "Investigate the encrypted volumes without protectionStatus=PROTECTED and "
                "re-trigger BitLocker key-protector backup for them."
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
        additional_findings=additional_findings,
        input_summary=input_summary,
        metadata={
            "transformationId": "isBitLockerRecoveryKeyEscrowed",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
