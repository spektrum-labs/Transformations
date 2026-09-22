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

    air_gapped_vaults = []
    other_vaults = []
    for v in vaults:
        if not isinstance(v, dict):
            continue
        vault_type = v.get("VaultType") or ""
        if vault_type == "LOGICALLY_AIR_GAPPED_BACKUP_VAULT":
            air_gapped_vaults.append(v)
        else:
            other_vaults.append(v)

    total_vaults = len(vaults)
    air_gapped_count = len(air_gapped_vaults)
    is_enabled = air_gapped_count > 0

    if is_enabled:
        names = [v.get("BackupVaultName") or "unknown" for v in air_gapped_vaults]
        pass_reasons = [
            f"Found {air_gapped_count} of {total_vaults} backup vault(s) with VaultType=LOGICALLY_AIR_GAPPED_BACKUP_VAULT: {', '.join(names)}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        vault_names = [v.get("BackupVaultName") or "unknown" for v in vaults]
        vault_types = list(set([v.get("VaultType") or "unknown" for v in vaults]))
        fail_reasons = [
            f"None of the {total_vaults} backup vault(s) found ({', '.join(vault_names)}) have VaultType=LOGICALLY_AIR_GAPPED_BACKUP_VAULT; observed types: {', '.join(vault_types)}."
        ]
        recommendations = [
            "Create a logically air-gapped backup vault using CreateLogicallyAirGappedBackupVault to isolate recovery points from the source account's control plane."
        ]

    result = {
        "isAirGappedStorageEnabled": is_enabled,
        "totalVaults": total_vaults,
        "airGappedVaultCount": air_gapped_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalVaults": total_vaults, "airGappedVaultCount": air_gapped_count},
        metadata={
            "transformationId": "isAirGappedStorageEnabled",
            "vendor": "AWS Backup",
            "category": "backup",
        },
    )
