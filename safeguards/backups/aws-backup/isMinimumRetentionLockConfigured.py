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
        vaults = data.get("BackupVaultList") or []
    else:
        vaults = []

    total_vaults = len(vaults)
    locked_with_min_retention = []
    locked_without_min_retention = []
    unlocked_vaults = []

    for v in vaults:
        if not isinstance(v, dict):
            continue
        name = v.get("BackupVaultName") or v.get("BackupVaultArn") or "unknown-vault"
        locked = bool(v.get("Locked"))
        min_retention = v.get("MinRetentionDays")
        if locked and isinstance(min_retention, (int, float)) and min_retention and min_retention > 0:
            locked_with_min_retention.append({"name": name, "minRetentionDays": min_retention})
        elif locked:
            locked_without_min_retention.append(name)
        else:
            unlocked_vaults.append(name)

    is_configured = len(locked_with_min_retention) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_configured:
        details = ", ".join(
            [f"{item['name']} (MinRetentionDays={item['minRetentionDays']})" for item in locked_with_min_retention]
        )
        pass_reasons.append(
            f"{len(locked_with_min_retention)} of {total_vaults} backup vault(s) have Vault Lock enabled with a MinRetentionDays floor set: {details}."
        )
    else:
        if total_vaults == 0:
            fail_reasons.append("No backup vaults were returned by listBackupVaults, so no minimum retention lock could be verified.")
        else:
            names = ", ".join([v for v in unlocked_vaults + locked_without_min_retention]) or "all vaults"
            fail_reasons.append(
                f"None of the {total_vaults} backup vault(s) have both Locked=true and a populated MinRetentionDays: {names}."
            )
        recommendations.append(
            "Apply a Vault Lock (PutBackupVaultLockConfiguration) with a MinRetentionDays value on the backup vault(s) storing compliance-relevant recovery points."
        )

    result = {
        "isMinimumRetentionLockConfigured": is_configured,
        "totalVaults": total_vaults,
        "vaultsWithMinRetentionLock": len(locked_with_min_retention),
    }

    input_summary = {
        "totalVaults": total_vaults,
        "lockedWithMinRetention": len(locked_with_min_retention),
        "lockedWithoutMinRetention": len(locked_without_min_retention),
        "unlockedVaults": len(unlocked_vaults),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMinimumRetentionLockConfigured",
            "vendor": "AWS Backup",
            "category": "backup",
        },
    )
