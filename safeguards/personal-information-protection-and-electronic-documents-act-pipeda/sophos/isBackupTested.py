"""
Transformation: isBackupTested
Vendor: Sophos  |  Category: personal-information-protection-and-electronic-documents-act-pipeda
Evaluates: Whether backup and recovery configurations have been validated via the Sophos Account Health Check -- assesses whether protection and policy checks indicate tested and verified backup posture.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTested", "vendor": "Sophos", "category": "personal-information-protection-and-electronic-documents-act-pipeda"}
        }
    }


def evaluate(data):
    try:
        checks = data.get("checks", {})
        overall = data.get("overall", {})

        if not checks and not overall:
            return {"isBackupTested": False, "error": "No health check data found in response"}

        overall_status = overall.get("status", "")
        is_healthy = overall_status.lower() in ["green", "good", "ok", "healthy"]

        endpoint_checks = checks.get("endpoint", {})
        server_checks = checks.get("server", {})

        endpoint_protection = endpoint_checks.get("protection", {})
        server_protection = server_checks.get("protection", {})

        endpoint_all_protected = not endpoint_protection.get("anyNotProtected", True)
        server_all_protected = not server_protection.get("anyNotProtected", True)

        endpoint_no_errors = not endpoint_checks.get("policy", {}).get("anyBadPolicy", False)
        server_no_errors = not server_checks.get("policy", {}).get("anyBadPolicy", False)

        has_checks = bool(checks)
        backup_posture_verified = has_checks and is_healthy and endpoint_all_protected and endpoint_no_errors

        return {
            "isBackupTested": backup_posture_verified,
            "overallStatus": overall_status,
            "endpointAllProtected": endpoint_all_protected,
            "serverAllProtected": server_all_protected,
            "endpointNoBadPolicy": endpoint_no_errors,
            "serverNoBadPolicy": server_no_errors
        }
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupTested"
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
            pass_reasons.append("Sophos health check confirms protection and policy checks indicate a verified backup posture")
            pass_reasons.append("Overall status: " + str(extra_fields.get("overallStatus", "unknown")))
            pass_reasons.append("All endpoints protected: " + str(extra_fields.get("endpointAllProtected", False)))
        else:
            fail_reasons.append("Backup posture could not be verified via Sophos Account Health Check")
            if not extra_fields.get("endpointAllProtected", False):
                fail_reasons.append("Some endpoints are not fully protected")
            if not extra_fields.get("endpointNoBadPolicy", False):
                fail_reasons.append("Bad policy configuration detected on endpoints")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Resolve all protection and policy issues identified in the Sophos Account Health Check")
            recommendations.append("Validate backup and recovery procedures through a manual test in addition to automated checks")
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
