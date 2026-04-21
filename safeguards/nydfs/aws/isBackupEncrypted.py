"""
Transformation: isBackupEncrypted
Vendor: AWS  |  Category: nydfs
Evaluates: Whether all AWS Backup vaults are encrypted with a KMS key.
"""
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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEncrypted", "vendor": "AWS", "category": "nydfs"}
        }
    }


def evaluate(data):
    try:
        vault_list = data.get("BackupVaultList", [])
        if not isinstance(vault_list, list):
            vault_list = []
        total_vaults = len(vault_list)
        encrypted_vaults = []
        unencrypted_vaults = []
        for vault in vault_list:
            vault_name = vault.get("BackupVaultName", vault.get("BackupVaultArn", "unknown"))
            encryption_key = vault.get("EncryptionKeyArn", "")
            if encryption_key and isinstance(encryption_key, str) and len(encryption_key.strip()) > 0:
                encrypted_vaults.append(vault_name)
            else:
                unencrypted_vaults.append(vault_name)
        if total_vaults == 0:
            is_encrypted = False
        else:
            is_encrypted = len(unencrypted_vaults) == 0
        encrypted_count = len(encrypted_vaults)
        unencrypted_count = len(unencrypted_vaults)
        score = 0
        if total_vaults > 0:
            score = (encrypted_count * 100) // total_vaults
        return {
            "isBackupEncrypted": is_encrypted,
            "totalVaults": total_vaults,
            "encryptedVaultCount": encrypted_count,
            "unencryptedVaultCount": unencrypted_count,
            "encryptionScoreInPercentage": score,
            "encryptedVaults": encrypted_vaults,
            "unencryptedVaults": unencrypted_vaults
        }
    except Exception as e:
        return {"isBackupEncrypted": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEncrypted"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total_vaults = eval_result.get("totalVaults", 0)
        encrypted_count = eval_result.get("encryptedVaultCount", 0)
        unencrypted_count = eval_result.get("unencryptedVaultCount", 0)
        score = eval_result.get("encryptionScoreInPercentage", 0)
        encrypted_vaults = eval_result.get("encryptedVaults", [])
        unencrypted_vaults = eval_result.get("unencryptedVaults", [])
        if result_value:
            pass_reasons.append("All " + str(total_vaults) + " AWS Backup vault(s) have a KMS EncryptionKeyArn configured.")
            pass_reasons.append("Encryption coverage: " + str(score) + "%.")
            if encrypted_vaults:
                additional_findings.append("Encrypted vaults: " + ", ".join([str(v) for v in encrypted_vaults]))
        else:
            if total_vaults == 0:
                fail_reasons.append("No AWS Backup vaults were found in this account/region. Unable to verify encryption.")
                recommendations.append("Create at least one AWS Backup vault with a KMS key assigned as the encryption key.")
            else:
                fail_reasons.append(str(unencrypted_count) + " of " + str(total_vaults) + " vault(s) do not have a KMS EncryptionKeyArn configured.")
                fail_reasons.append("Encryption coverage: " + str(score) + "%.")
                recommendations.append("Assign a KMS key to every AWS Backup vault. Note: AWS Backup vaults can only be assigned a KMS key at creation time — unencrypted vaults must be recreated.")
                if unencrypted_vaults:
                    additional_findings.append("Unencrypted vaults: " + ", ".join([str(v) for v in unencrypted_vaults]))
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalVaults": total_vaults, "encryptedVaultCount": encrypted_count, "unencryptedVaultCount": unencrypted_count, "isBackupEncrypted": result_value}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
