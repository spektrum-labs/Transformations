import json
from datetime import datetime

# AWS Backup BackupVaultListMember.EncryptionKeyType documents exactly two values:
# CUSTOMER_MANAGED_KMS_KEY and AWS_OWNED_KMS_KEY. AWS_MANAGED is not documented but is kept
# as AWS-owned, because reading it that way can only fail the check, never pass it.
CUSTOMER_MANAGED_TYPES = ("CUSTOMER_MANAGED_KMS_KEY",)
AWS_OWNED_TYPES = ("AWS_OWNED_KMS_KEY", "AWS_MANAGED")


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

    total_vaults = len(vaults)
    customer_managed_vaults = []
    aws_managed_vaults = []
    unknown_type_vaults = []

    for v in vaults:
        if not isinstance(v, dict):
            continue
        name = v.get("BackupVaultName") or v.get("BackupVaultArn") or "unknown-vault"
        key_type = v.get("EncryptionKeyType")
        key_arn = v.get("EncryptionKeyArn")
        if key_type in CUSTOMER_MANAGED_TYPES:
            customer_managed_vaults.append((name, key_arn))
        elif key_type in AWS_OWNED_TYPES:
            aws_managed_vaults.append((name, key_arn))
        else:
            unknown_type_vaults.append((name, key_arn, key_type))

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    api_errors = []

    # Verdict (ENG-1351):
    #   False -- any vault reports an AWS-owned key: a measured gap, whatever else is unknown.
    #   True  -- every vault reports the documented customer-managed type.
    #   None  -- no vaults, or some vaults report no or an unrecognised type and none is
    #            AWS-owned, so customer-managed use cannot be confirmed either way.
    if aws_managed_vaults:
        is_customer_managed = False
    elif total_vaults > 0 and customer_managed_vaults and not unknown_type_vaults:
        is_customer_managed = True
    else:
        is_customer_managed = None

    if total_vaults == 0:
        reason = "No backup vaults were returned by ListBackupVaults, so the KMS key type could not be measured."
        fail_reasons.append(reason)
        api_errors.append(reason)
        recommendations.append("Verify AWS Backup vaults exist in this account/region and that the integration role has backup:ListBackupVaults permission.")
    else:
        if customer_managed_vaults:
            names = ", ".join([n for n, _ in customer_managed_vaults])
            pass_reasons.append(
                f"{len(customer_managed_vaults)} of {total_vaults} vault(s) report EncryptionKeyType=CUSTOMER_MANAGED_KMS_KEY: {names}."
            )
        if aws_managed_vaults:
            names = ", ".join([n for n, _ in aws_managed_vaults])
            fail_reasons.append(
                f"{len(aws_managed_vaults)} of {total_vaults} vault(s) report EncryptionKeyType=AWS_OWNED_KMS_KEY (an AWS-owned key, not customer-managed): {names}."
            )
        if unknown_type_vaults:
            details = ", ".join([f"{n} (EncryptionKeyType={t}, EncryptionKeyArn={arn})" for n, arn, t in unknown_type_vaults])
            reason = (
                f"{len(unknown_type_vaults)} of {total_vaults} vault(s) did not report a recognised EncryptionKeyType, "
                f"so customer-managed KMS use could not be confirmed from this response: {details}."
            )
            fail_reasons.append(reason)
            if is_customer_managed is None:
                api_errors.append(reason)
            recommendations.append(
                "Query AWS KMS DescribeKey for each vault's EncryptionKeyArn to confirm KeyManager=CUSTOMER, since ListBackupVaults did not report a recognised EncryptionKeyType for these vaults."
            )

    result = {
        "isVaultManagedKMSEnabled": is_customer_managed,
        "totalVaults": total_vaults,
        "customerManagedVaultCount": len(customer_managed_vaults),
        "awsManagedVaultCount": len(aws_managed_vaults),
        "unknownKeyTypeVaultCount": len(unknown_type_vaults),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        api_errors=api_errors,
        input_summary={
            "totalVaults": total_vaults,
            "customerManagedVaultCount": len(customer_managed_vaults),
            "awsManagedVaultCount": len(aws_managed_vaults),
            "unknownKeyTypeVaultCount": len(unknown_type_vaults),
        },
        metadata={
            "transformationId": "isVaultManagedKMSEnabled",
            "vendor": "AWS Backup",
            "category": "backup",
        },
    )
