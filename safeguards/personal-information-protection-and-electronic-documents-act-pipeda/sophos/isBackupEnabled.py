"""
Transformation: isBackupEnabled
Vendor: Sophos  |  Category: personal-information-protection-and-electronic-documents-act-pipeda
Evaluates: Whether backup-relevant protection settings and data protection policies are active in Sophos Central via the Account Health Check response.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabled", "vendor": "Sophos", "category": "personal-information-protection-and-electronic-documents-act-pipeda"}
        }
    }


def evaluate(data):
    try:
        checks = data.get("checks", {})
        overall = data.get("overall", {})

        if not checks and not overall:
            return {"isBackupEnabled": False, "error": "No health check data found in response"}

        overall_status = overall.get("status", "")
        status_ok = overall_status.lower() in ["green", "good", "ok", "healthy"]

        endpoint_checks = checks.get("endpoint", {})
        server_checks = checks.get("server", {})
        has_protection_checks = bool(endpoint_checks) or bool(server_checks)

        endpoint_protection = endpoint_checks.get("protection", {})
        any_not_protected = endpoint_protection.get("anyNotProtected", False)
        any_tampered = endpoint_protection.get("anyTampered", False)

        is_enabled = has_protection_checks and status_ok and not any_not_protected and not any_tampered

        return {
            "isBackupEnabled": is_enabled,
            "overallStatus": overall_status,
            "hasProtectionChecks": has_protection_checks,
            "anyEndpointNotProtected": any_not_protected,
            "anyTampered": any_tampered
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
        if result_value:
            pass_reasons.append("Sophos Central protection and data security checks are active and healthy")
            pass_reasons.append("Overall health status: " + str(extra_fields.get("overallStatus", "unknown")))
        else:
            fail_reasons.append("Backup-relevant protection settings are not fully active in Sophos Central")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable and verify data protection policies in Sophos Central")
            recommendations.append("Ensure all endpoints are protected and health check status is green")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
