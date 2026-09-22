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

    locked_vaults = []
    compliance_vaults = []
    governance_vaults = []
    ambiguous_vaults = []

    for v in vaults:
        if not isinstance(v, dict):
            continue
        locked = v.get("Locked")
        if not locked:
            continue
        locked_vaults.append(v)
        lock_date = v.get("LockDate")
        creation_date = v.get("CreationDate")
        name = v.get("BackupVaultName") or v.get("BackupVaultArn") or "unknown-vault"

        if lock_date and creation_date:
            gap_days = (lock_date - creation_date) / 86400.0
            if gap_days > 1:
                compliance_vaults.append({"name": name, "gap_days": gap_days})
            else:
                governance_vaults.append({"name": name, "gap_days": gap_days})
        elif lock_date and not creation_date:
            compliance_vaults.append({"name": name, "gap_days": None})
        else:
            ambiguous_vaults.append(name)

    total_vaults = len(vaults)
    total_locked = len(locked_vaults)
    is_compliance_enabled = len(compliance_vaults) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_compliance_enabled:
        names = ", ".join([c["name"] for c in compliance_vaults])
        pass_reasons.append(
            f"Found {len(compliance_vaults)} locked vault(s) with a future LockDate relative to CreationDate "
            f"(cooling-off gap from a ChangeableForDays grace period): {names}. Out of {total_locked} locked "
            f"vault(s) total across {total_vaults} vault(s) scanned."
        )
    else:
        if total_locked == 0:
            fail_reasons.append(
                f"No locked backup vaults found. Scanned {total_vaults} vault(s); all have Locked=false, "
                f"so no vault lock (governance or compliance mode) is currently applied."
            )
            recommendations.append(
                "Apply a vault lock via PutBackupVaultLockConfiguration to at least one backup vault to "
                "enable compliance mode protection against deletion or retention shortening."
            )
        else:
            names = ", ".join([g["name"] for g in governance_vaults]) if governance_vaults else ", ".join(ambiguous_vaults)
            fail_reasons.append(
                f"Found {total_locked} locked vault(s), but none show a future LockDate cooling-off gap "
                f"indicative of compliance mode: {names}. These appear to be locked without the "
                f"ChangeableForDays cooling-off signature."
            )
            recommendations.append(
                "Review PutBackupVaultLockConfiguration settings for the locked vault(s) to confirm whether "
                "a ChangeableForDays grace period was applied, and reconfigure without it if compliance mode "
                "enforcement is required."
            )

    result = {
        "isDataLockComplianceModeEnabled": is_compliance_enabled,
        "totalVaults": total_vaults,
        "lockedVaultsCount": total_locked,
        "complianceModeVaultsCount": len(compliance_vaults),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalVaults": total_vaults,
            "lockedVaultsCount": total_locked,
            "complianceModeVaultsCount": len(compliance_vaults),
            "governanceModeVaultsCount": len(governance_vaults),
        },
        metadata={
            "transformationId": "isDataLockComplianceModeEnabled",
            "vendor": "AWS Backup",
            "category": "backup",
        },
    )
