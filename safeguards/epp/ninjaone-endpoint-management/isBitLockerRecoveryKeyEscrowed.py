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
        results = data
    elif isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
    else:
        results = []

    if not isinstance(results, list):
        results = []

    # Only volumes that carry a bitLockerStatus (or similar encryption status) block
    # are candidates for BitLocker recovery-key escrow evaluation.
    candidate_volumes = []
    for vol in results:
        if not isinstance(vol, dict):
            continue
        bls = vol.get("bitLockerStatus")
        if isinstance(bls, dict):
            candidate_volumes.append((vol, bls))

    total_candidates = len(candidate_volumes)
    total_volumes_seen = len(results)

    escrowed_count = 0
    protected_but_not_escrowed = 0
    escrowed_samples = []

    for vol, bls in candidate_volumes:
        protection_status = str(bls.get("protectionStatus") or "").upper()
        initialized = bool(bls.get("initializedForProtection"))
        recovery_backed_up = bls.get("recoveryKeyBackedUp")
        recovery_escrowed_flag = bls.get("recoveryPasswordEscrowed")
        key_protectors = bls.get("keyProtectors") or []

        is_protected = protection_status in ("PROTECTED", "ON") or initialized

        escrow_evidence = False
        if recovery_backed_up is True or recovery_escrowed_flag is True:
            escrow_evidence = True
        elif isinstance(key_protectors, list):
            for kp in key_protectors:
                if isinstance(kp, dict) and kp.get("backedUp") is True:
                    escrow_evidence = True
                    break

        if is_protected and escrow_evidence:
            escrowed_count = escrowed_count + 1
            if len(escrowed_samples) < 5:
                escrowed_samples.append(vol.get("name") or vol.get("driveLetter") or "unknown")
        elif is_protected and not escrow_evidence:
            protected_but_not_escrowed = protected_but_not_escrowed + 1

    if total_candidates == 0:
        is_escrowed = False
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_volumes_seen} volume records returned by getVolumesReport include a "
            "bitLockerStatus block with recovery-key escrow indicators (recoveryKeyBackedUp / "
            "recoveryPasswordEscrowed / keyProtectors[].backedUp), so escrow status cannot be confirmed."
        ]
        recommendations = [
            "Verify BitLocker Manage-BDE reporting is enabled in the NinjaOne policy so bitLockerStatus "
            "fields (protectionStatus, recoveryKeyBackedUp) populate for encrypted volumes."
        ]
    elif escrowed_count > 0:
        is_escrowed = True
        pass_reasons = [
            f"{escrowed_count} of {total_candidates} volumes with a bitLockerStatus record show "
            f"protectionStatus=PROTECTED/ON with a backed-up recovery key protector, e.g. volumes: "
            f"{', '.join([str(s) for s in escrowed_samples])}."
        ]
        fail_reasons = []
        if protected_but_not_escrowed > 0:
            fail_reasons = [
                f"{protected_but_not_escrowed} additional protected volumes do not show recovery-key "
                "escrow evidence."
            ]
        recommendations = []
    else:
        is_escrowed = False
        pass_reasons = []
        fail_reasons = [
            f"{total_candidates} volumes report a bitLockerStatus block, but none show "
            "recoveryKeyBackedUp/recoveryPasswordEscrowed=true or a backed-up key protector "
            f"({protected_but_not_escrowed} are protection-enabled without escrow evidence)."
        ]
        recommendations = [
            "Ensure BitLocker recovery keys are backed up to NinjaOne (or Active Directory/Azure AD) "
            "for all protected volumes so escrow status can be confirmed."
        ]

    result = {
        "isBitLockerRecoveryKeyEscrowed": is_escrowed,
        "totalVolumesSeen": total_volumes_seen,
        "volumesWithBitLockerStatus": total_candidates,
        "volumesWithEscrowedRecoveryKey": escrowed_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalVolumesSeen": total_volumes_seen,
            "volumesWithBitLockerStatus": total_candidates,
            "volumesWithEscrowedRecoveryKey": escrowed_count,
        },
        metadata={
            "transformationId": "isBitLockerRecoveryKeyEscrowed",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
