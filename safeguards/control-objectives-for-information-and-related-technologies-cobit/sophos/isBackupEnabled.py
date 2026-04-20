"""
Transformation: isBackupEnabled
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Check whether backup/recovery protection is enabled. Evaluates the account health
check response for backup-related checks or CryptoGuard/data recovery protection indicators.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabled", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        checks = data.get("checks", {})
        overall = data.get("overall", "")
        backup_keywords = ["backup", "cryptoguard", "recovery", "ransomware", "fileRecovery", "dataRecovery"]
        backup_check_found = False
        backup_check_key = ""
        for key in checks:
            key_lower = key.lower()
            for kw in backup_keywords:
                if kw.lower() in key_lower:
                    backup_check_found = True
                    backup_check_key = key
                    break
            if backup_check_found:
                break
        protection = checks.get("protection", {})
        has_cryptoguard = False
        for key in protection:
            if "crypto" in key.lower() or "ransomware" in key.lower() or "filerecovery" in key.lower():
                has_cryptoguard = True
                break
        is_backup_enabled = backup_check_found or has_cryptoguard or (overall in ["good", "ok"])
        return {
            "isBackupEnabled": is_backup_enabled,
            "overallHealthStatus": overall,
            "backupCheckFound": backup_check_found,
            "backupCheckKey": backup_check_key,
            "hasCryptoGuardOrRecovery": has_cryptoguard
        }
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabled"
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
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        if result_value:
            pass_reasons.append("Backup or data recovery protection indicators found in account health check")
            pass_reasons.append("overallHealthStatus: " + str(extra_fields.get("overallHealthStatus", "")))
            if extra_fields.get("backupCheckFound"):
                pass_reasons.append("Backup-related check key: " + str(extra_fields.get("backupCheckKey", "")))
            if extra_fields.get("hasCryptoGuardOrRecovery"):
                pass_reasons.append("CryptoGuard or ransomware file recovery protection detected")
        else:
            fail_reasons.append("No backup or data recovery protection indicators found in account health check")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable CryptoGuard and ransomware file recovery features in Sophos endpoint policies to provide backup-level data protection")
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"overallHealthStatus": extra_fields.get("overallHealthStatus", ""), "backupCheckFound": extra_fields.get("backupCheckFound", False)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
