"""
Transformation: isBackupEncrypted
Vendor: Sophos  |  Category: Backups
Evaluates: Inspects endpoint protection policies to verify that encryption-related
settings are configured and enabled across assigned backup and data protection policies.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEncrypted", "vendor": "Sophos", "category": "Backups"}
        }
    }


def settings_has_encryption(settings, depth):
    if not settings or depth <= 0:
        return False
    for key in settings:
        key_lower = key.lower()
        if "encrypt" in key_lower or "cipher" in key_lower or "aes" in key_lower:
            val = settings[key]
            if val is True or val == "enabled" or val == "true" or val == 1:
                return True
            if isinstance(val, str) and val.lower() not in ["false", "disabled", "none", ""]:
                return True
        val = settings[key]
        if isinstance(val, dict):
            if settings_has_encryption(val, depth - 1):
                return True
    return False


def policy_has_encryption(policy):
    ptype = policy.get("type", "").lower()
    name = policy.get("name", "").lower()
    settings = policy.get("settings", {})

    if "encryption" in ptype or "device-encryption" in ptype or "bitlocker" in ptype or "filevault" in ptype:
        return True
    if "encrypt" in name:
        return True
    if settings and settings_has_encryption(settings, 4):
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {
                "isBackupEncrypted": False,
                "totalPolicies": 0,
                "enabledPolicies": 0,
                "encryptionEnabledPolicies": 0,
                "encryptionPolicyNames": []
            }

        total = len(items)
        enabled_count = 0
        encryption_count = 0
        encryption_names = []
        all_policy_types = []

        for policy in items:
            enabled = policy.get("enabled", False)
            ptype = policy.get("type", "")
            name = policy.get("name", "")

            if enabled:
                enabled_count = enabled_count + 1

            if ptype and ptype not in all_policy_types:
                all_policy_types.append(ptype)

            if enabled and policy_has_encryption(policy):
                encryption_count = encryption_count + 1
                encryption_names.append(name if name else "unnamed-policy")

        result = encryption_count > 0

        return {
            "isBackupEncrypted": result,
            "totalPolicies": total,
            "enabledPolicies": enabled_count,
            "encryptionEnabledPolicies": encryption_count,
            "encryptionPolicyNames": encryption_names,
            "observedPolicyTypes": all_policy_types
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

        enc_count = extra_fields.get("encryptionEnabledPolicies", 0)
        total = extra_fields.get("totalPolicies", 0)
        enc_names = extra_fields.get("encryptionPolicyNames", [])
        policy_types = extra_fields.get("observedPolicyTypes", [])

        if result_value:
            pass_reasons.append("Encryption-enabled policies found: " + str(enc_count) + " of " + str(total) + " total policies")
            if enc_names:
                pass_reasons.append("Encryption policies: " + ", ".join(enc_names))
        else:
            fail_reasons.append("No enabled encryption policies found in Sophos Central endpoint policies")
            fail_reasons.append("Total policies scanned: " + str(total))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable device encryption policies (BitLocker/FileVault) in Sophos Central to protect backup data at rest")
            recommendations.append("Assign encryption policies to all endpoint groups to ensure backup data is encrypted")

        if policy_types:
            additional_findings.append("Observed policy types: " + ", ".join(policy_types))

        result_dict = {"isBackupEncrypted": result_value}
        for k, v in extra_fields.items():
            result_dict[k] = v

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPolicies": total, "encryptionEnabledPolicies": enc_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
