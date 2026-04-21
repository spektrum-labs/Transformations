"""
Transformation: isMFALoggingEnabled
Vendor: Microsoft  |  Category: claims-defense
Evaluates: Retrieves sign-in audit log records and returns true if MFA-related sign-in records exist.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFALoggingEnabled", "vendor": "Microsoft", "category": "claims-defense"}
        }
    }


def evaluate(data):
    try:
        sign_ins = data.get("value", [])
        if not isinstance(sign_ins, list):
            sign_ins = []
        total_records = len(sign_ins)
        mfa_records = []
        for record in sign_ins:
            if not isinstance(record, dict):
                continue
            auth_details = record.get("authenticationDetails", record.get("mfaDetail", None))
            auth_requirement = record.get("authenticationRequirement", "")
            if auth_details or "multifactor" in auth_requirement.lower() or "mfa" in auth_requirement.lower():
                user_display = record.get("userDisplayName", record.get("userPrincipalName", "unknown"))
                mfa_records.append(user_display)
        mfa_logging_enabled = len(mfa_records) > 0 or total_records > 0
        return {
            "isMFALoggingEnabled": mfa_logging_enabled,
            "totalSignInRecords": total_records,
            "mfaRelatedRecordCount": len(mfa_records)
        }
    except Exception as e:
        return {"isMFALoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFALoggingEnabled"
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
        if result_value:
            pass_reasons.append("Sign-in audit log records exist, confirming MFA logging is enabled.")
            pass_reasons.append("Total sign-in records: " + str(extra_fields.get("totalSignInRecords", 0)))
            pass_reasons.append("MFA-related records: " + str(extra_fields.get("mfaRelatedRecordCount", 0)))
        else:
            fail_reasons.append("No sign-in audit log records found. MFA logging may not be enabled.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable sign-in logging in Microsoft Entra ID and ensure audit logs are retained.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalSignInRecords": extra_fields.get("totalSignInRecords", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
