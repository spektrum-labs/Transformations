"""
Transformation: isBackupEncrypted
Vendor: CrashPlan  |  Category: nydfs
Evaluates: Whether CrashPlan backup encryption is enforced at the org level.
CrashPlan applies AES-256 encryption at rest and TLS in transit by default.
Org settings are inspected to confirm encryption is active and not overridden
by a weakened or unsupported custom-key configuration.
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupEncrypted",
                "vendor": "CrashPlan",
                "category": "nydfs"
            }
        }
    }


def evaluate(data):
    try:
        org = data.get("org", data)
        org_name = data.get("orgName", org.get("orgName", ""))
        org_id = data.get("orgId", org.get("orgId", None))
        settings = data.get("settings", org.get("settings", {}))
        if not org and not settings:
            return {
                "isBackupEncrypted": False,
                "error": "No org data returned — unable to confirm encryption configuration"
            }
        org_data_present = bool(org_name or org_id is not None)
        encryption_weakened = False
        encryption_mode = "AES-256 (platform default)"
        custom_key_in_use = False
        additional_notes = []
        if settings:
            custom_key_val = settings.get("isUsingAccountCustomKey", settings.get("customKeyEnabled", None))
            if custom_key_val is True:
                custom_key_in_use = True
                additional_notes.append("Org is using a customer-managed custom encryption key")
            encryption_disabled = settings.get("archiveEncryptionEnabled", None)
            if encryption_disabled is False:
                encryption_weakened = True
                additional_notes.append("archiveEncryptionEnabled is explicitly set to false")
            enc_mode = settings.get("encryptionMode", settings.get("archiveEncryptionMode", None))
            if enc_mode:
                encryption_mode = str(enc_mode)
        is_encrypted = org_data_present and not encryption_weakened
        return {
            "isBackupEncrypted": is_encrypted,
            "orgName": org_name,
            "encryptionMode": encryption_mode,
            "customKeyInUse": custom_key_in_use,
            "encryptionWeakened": encryption_weakened,
            "additionalNotes": additional_notes
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        org_name_str = str(eval_result.get("orgName", ""))
        enc_mode_str = str(eval_result.get("encryptionMode", "AES-256 (platform default)"))
        if result_value:
            pass_reasons.append("CrashPlan backup encryption is confirmed active for org: " + org_name_str)
            pass_reasons.append("Encryption mode: " + enc_mode_str)
            pass_reasons.append("CrashPlan enforces AES-256 encryption at rest and TLS in transit by default")
            if eval_result.get("customKeyInUse"):
                additional_findings.append("Customer-managed custom encryption key is in use — ensure key management meets NYDFS requirements")
        else:
            fail_reasons.append("Backup encryption could not be confirmed or is explicitly disabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if eval_result.get("encryptionWeakened"):
                fail_reasons.append("Archive encryption has been explicitly disabled in org settings")
            recommendations.append("Verify org encryption settings in the CrashPlan console under Administration > Security")
            recommendations.append("Ensure archiveEncryptionEnabled is not set to false in org configuration")
        extra_notes = eval_result.get("additionalNotes", [])
        for note in extra_notes:
            additional_findings.append(note)
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "orgName": eval_result.get("orgName", ""),
                "encryptionMode": eval_result.get("encryptionMode", ""),
                "customKeyInUse": eval_result.get("customKeyInUse", False)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
