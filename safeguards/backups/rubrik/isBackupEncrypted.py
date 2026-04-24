"""
Transformation: isBackupEncrypted
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether backup data is encrypted at rest on the Rubrik cluster.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEncrypted", "vendor": "Rubrik", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"isBackupEncrypted": False, "error": "Unexpected response format"}

        if "encryptionEnabled" in data:
            enabled = bool(data["encryptionEnabled"])
            enc_type = str(data.get("encryptionType", data.get("type", "Unknown")))
            return {"isBackupEncrypted": enabled, "encryptionType": enc_type}

        if "isEncryptionEnabled" in data:
            enabled = bool(data["isEncryptionEnabled"])
            enc_type = str(data.get("encryptionType", "Unknown"))
            return {"isBackupEncrypted": enabled, "encryptionType": enc_type}

        if "dataEncryption" in data:
            enc_obj = data["dataEncryption"]
            if isinstance(enc_obj, bool):
                return {"isBackupEncrypted": enc_obj, "encryptionType": "Unknown"}
            if isinstance(enc_obj, dict):
                enabled = bool(enc_obj.get("enabled", enc_obj.get("isEnabled", False)))
                enc_type = str(enc_obj.get("type", enc_obj.get("algorithm", "Unknown")))
                return {"isBackupEncrypted": enabled, "encryptionType": enc_type}

        if "encryptionConfig" in data:
            cfg = data["encryptionConfig"]
            if isinstance(cfg, dict):
                enabled = bool(cfg.get("enabled", cfg.get("isEnabled", False)))
                enc_type = str(cfg.get("type", cfg.get("algorithm", "Unknown")))
                key_mgmt = str(cfg.get("keyManagement", cfg.get("keyManagementType", "Unknown")))
                return {"isBackupEncrypted": enabled, "encryptionType": enc_type, "keyManagement": key_mgmt}

        if "data" in data and isinstance(data["data"], list):
            sla_list = data["data"]
            encrypted_count = 0
            total_count = len(sla_list)
            for domain in sla_list:
                if not isinstance(domain, dict):
                    continue
                if domain.get("encryptionEnabled") or domain.get("isEncrypted") or domain.get("dataEncryption"):
                    encrypted_count = encrypted_count + 1
            if total_count > 0:
                all_encrypted = encrypted_count == total_count
                return {
                    "isBackupEncrypted": all_encrypted,
                    "encryptedDomains": encrypted_count,
                    "totalDomains": total_count,
                    "encryptionType": "SLA Domain Level"
                }

        enc_mode = str(data.get("encryptionMode", data.get("mode", ""))).upper()
        if enc_mode and enc_mode not in ["", "NONE", "DISABLED", "OFF"]:
            return {"isBackupEncrypted": True, "encryptionType": enc_mode}
        if enc_mode in ["NONE", "DISABLED", "OFF"]:
            return {"isBackupEncrypted": False, "encryptionType": enc_mode}

        return {"isBackupEncrypted": False, "error": "Could not determine encryption status from response"}
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
        if result_value:
            pass_reasons.append("Rubrik backup data encryption is enabled")
            if "encryptionType" in extra_fields:
                additional_findings.append("Encryption type: " + str(extra_fields["encryptionType"]))
            if "keyManagement" in extra_fields:
                additional_findings.append("Key management: " + str(extra_fields["keyManagement"]))
            if "encryptedDomains" in extra_fields:
                additional_findings.append("Encrypted SLA domains: " + str(extra_fields["encryptedDomains"]) + " / " + str(extra_fields.get("totalDomains", "?")))
        else:
            fail_reasons.append("Rubrik backup encryption is not confirmed as enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable at-rest data encryption in the Rubrik cluster security settings")
            recommendations.append("Consider hardware-based encryption (FIPS mode) for compliance requirements")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "encryptionType": extra_fields.get("encryptionType", "Unknown")}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
