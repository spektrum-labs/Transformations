import json
from datetime import datetime


def extract_input(input_data):
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

    locked_vaults = [v for v in vaults if isinstance(v, dict) and v.get("Locked") is True]
    governance_vaults = []
    compliance_vaults = []
    for v in locked_vaults:
        lock_date = v.get("LockDate")
        name = v.get("BackupVaultName") or v.get("BackupVaultArn") or "unknown-vault"
        if lock_date is None:
            governance_vaults.append(name)
        else:
            compliance_vaults.append(name)

    is_governance_enabled = len(governance_vaults) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    total_vaults = len(vaults)
    total_locked = len(locked_vaults)

    if is_governance_enabled:
        pass_reasons.append(
            "Found %d locked vault(s) with Locked=true and LockDate=null (%s), which is the signature of Governance mode vault lock (no immediate permanent cooling-off gap)."
            % (len(governance_vaults), ", ".join(governance_vaults))
        )
    else:
        if total_locked == 0:
            fail_reasons.append(
                "None of the %d vaults returned by listBackupVaults have Locked=true; no vault lock (governance or compliance) is configured."
                % total_vaults
            )
            recommendations.append(
                "Apply a vault lock via PutBackupVaultLockConfiguration with a ChangeableForDays grace period to enable Governance mode."
            )
        else:
            fail_reasons.append(
                "Found %d locked vault(s) (%s) but all have a non-null LockDate, indicating Compliance mode rather than Governance mode."
                % (total_locked, ", ".join(compliance_vaults))
            )
            recommendations.append(
                "To enable Governance mode, apply a vault lock with a ChangeableForDays value and confirm the resulting vault shows Locked=true with LockDate=null during the grace window."
            )

    result = {
        "isBackupVaultLockGovernanceModeEnabled": is_governance_enabled,
        "totalVaults": total_vaults,
        "lockedVaultsCount": total_locked,
        "governanceModeVaultsCount": len(governance_vaults),
        "complianceModeVaultsCount": len(compliance_vaults),
    }

    input_summary = {
        "totalVaults": total_vaults,
        "lockedVaultsCount": total_locked,
        "governanceModeVaultsCount": len(governance_vaults),
        "complianceModeVaultsCount": len(compliance_vaults),
    }

    metadata = {
        "transformationId": "isBackupVaultLockGovernanceModeEnabled",
        "vendor": "AWS Backup",
        "category": "backup",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
