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
    total_recovery_points = 0
    for v in vaults:
        if isinstance(v, dict):
            rp = v.get("NumberOfRecoveryPoints") or 0
            total_recovery_points = total_recovery_points + rp

    vault_names = [v.get("BackupVaultName") for v in vaults if isinstance(v, dict)]

    is_configured = total_vaults > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_configured:
        pass_reasons.append(
            f"Found {total_vaults} backup vault(s) in the account/region: {vault_names}. "
            f"Total recovery points across all vaults: {total_recovery_points}."
        )
    else:
        fail_reasons.append(
            "No backup vaults were returned by ListBackupVaults for this account/region."
        )
        recommendations.append(
            "Create at least one AWS Backup vault (CreateBackupVault) in this region to configure cloud backup."
        )

    result = {
        "isCloudBackupConfigured": is_configured,
        "totalVaults": total_vaults,
        "totalRecoveryPoints": total_recovery_points,
        "vaultNames": vault_names,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalVaults": total_vaults, "totalRecoveryPoints": total_recovery_points},
        metadata={
            "transformationId": "isCloudBackupConfigured",
            "vendor": "AWS Backup",
            "category": "backup",
        },
    )
