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
        vaults = data
    elif isinstance(data, dict):
        vaults = data.get("BackupVaultList") or data.get("data") or []
    else:
        vaults = []

    total_vaults = len(vaults)
    total_recovery_points = 0
    locked_vaults = []
    locked_vaults_with_recovery_points = 0

    for v in vaults:
        if not isinstance(v, dict):
            continue
        rp = v.get("NumberOfRecoveryPoints") or 0
        total_recovery_points = total_recovery_points + rp
        locked = bool(v.get("Locked"))
        if locked:
            locked_vaults.append(v.get("BackupVaultName"))
            if rp > 0:
                locked_vaults_with_recovery_points = locked_vaults_with_recovery_points + 1

    is_enforced = locked_vaults_with_recovery_points > 0

    input_summary = {
        "totalVaults": total_vaults,
        "totalRecoveryPoints": total_recovery_points,
        "lockedVaultCount": len(locked_vaults),
        "lockedVaultsWithRecoveryPoints": locked_vaults_with_recovery_points,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enforced:
        pass_reasons.append(
            "%d of %d backup vault(s) have Locked=true and hold recovery points (names: %s), enforcing WORM/read-only semantics on their stored snapshots per AWS Backup Vault Lock." % (
                locked_vaults_with_recovery_points, total_vaults, ", ".join([n for n in locked_vaults if n])
            )
        )
    else:
        vault_names = ", ".join([v.get("BackupVaultName", "unknown") for v in vaults if isinstance(v, dict)])
        fail_reasons.append(
            "None of the %d backup vault(s) inspected (%s) have Locked=true. Recovery points totaling %d across these vaults are not protected by AWS Backup Vault Lock, so they remain deletable/modifiable." % (
                total_vaults, vault_names, total_recovery_points
            )
        )
        recommendations.append(
            "Apply a Vault Lock configuration (PutBackupVaultLockConfiguration) to backup vaults that hold recovery points, so recovery points become immutable (WORM) and cannot be deleted or modified."
        )

    result = {
        "isReadOnlySnapshotEnforced": is_enforced,
        "totalVaults": total_vaults,
        "lockedVaultCount": len(locked_vaults),
        "totalRecoveryPoints": total_recovery_points,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isReadOnlySnapshotEnforced",
            "vendor": "AWS Backup",
            "category": "backup",
        },
    )
