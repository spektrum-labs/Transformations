"""
Transformation: isBackupEncrypted
Vendor: Veeam  |  Category: Backup
Evaluates: Whether at least one encryption password is configured in Veeam Backup & Replication,
           indicating backup encryption has been set up, based on GET /api/v1/encryptionPasswords.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEncrypted", "vendor": "Veeam", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        passwords = data.get("data", [])
        if not isinstance(passwords, list):
            passwords = []
        total_passwords = len(passwords)
        is_encrypted = total_passwords > 0
        password_hints = []
        for pw in passwords:
            hint = pw.get("hint", pw.get("description", pw.get("id", "Unnamed")))
            password_hints.append(str(hint))
        return {
            "isBackupEncrypted": is_encrypted,
            "totalEncryptionPasswords": total_passwords,
            "encryptionPasswordHints": password_hints
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
        total_passwords = eval_result.get("totalEncryptionPasswords", 0)
        hints = eval_result.get("encryptionPasswordHints", [])
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append(str(total_passwords) + " encryption password(s) configured in Veeam Backup and Replication")
            if hints:
                additional_findings.append("Configured encryption entries: " + ", ".join(hints))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("No encryption passwords found — backup encryption is not configured")
                recommendations.append("Configure at least one encryption password in Veeam to enable backup encryption")
                recommendations.append("Navigate to Home > Encryption Passwords in the Veeam console and add a password")
        return create_response(
            result={criteriaKey: result_value, "totalEncryptionPasswords": total_passwords},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalEncryptionPasswords": total_passwords})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
