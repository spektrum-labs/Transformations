"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: iam
Evaluates: Confirms audit logging is active by checking that both authentication event logs
and administrator action logs are being captured and contain entries.
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
                "transformationId": "isAuditLoggingEnabled",
                "vendor": "Duo",
                "category": "iam"
            }
        }
    }


def evaluate(data):
    try:
        authlogs = data.get("authlogs", [])
        adminlogs = data.get("adminlogs", [])

        if not isinstance(authlogs, list):
            authlogs = []
        if not isinstance(adminlogs, list):
            adminlogs = []

        auth_log_count = len(authlogs)
        admin_log_count = len(adminlogs)
        auth_logs_present = auth_log_count > 0
        admin_logs_present = admin_log_count > 0
        is_audit_logging_enabled = auth_logs_present and admin_logs_present

        return {
            "isAuditLoggingEnabled": is_audit_logging_enabled,
            "authLogCount": auth_log_count,
            "adminLogCount": admin_log_count,
            "authLogsPresent": auth_logs_present,
            "adminLogsPresent": admin_logs_present
        }
    except Exception as e:
        return {"isAuditLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAuditLoggingEnabled"
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
        auth_log_count = eval_result.get("authLogCount", 0)
        admin_log_count = eval_result.get("adminLogCount", 0)
        auth_logs_present = eval_result.get("authLogsPresent", False)
        admin_logs_present = eval_result.get("adminLogsPresent", False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Both authentication and administrator audit logs are active and contain entries")
            pass_reasons.append("authLogCount: " + str(auth_log_count))
            pass_reasons.append("adminLogCount: " + str(admin_log_count))
        else:
            if not auth_logs_present:
                fail_reasons.append("Authentication event logs are empty or not being captured")
                recommendations.append("Verify Duo authentication log collection is enabled and the Admin API application has the 'Grant read log' permission")
            if not admin_logs_present:
                fail_reasons.append("Administrator action logs are empty or not being captured")
                recommendations.append("Verify Duo administrator audit log collection is enabled and the Admin API application has the 'Grant read log' permission")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not fail_reasons:
                fail_reasons.append("isAuditLoggingEnabled check failed")

        result = {
            "isAuditLoggingEnabled": result_value,
            "authLogCount": auth_log_count,
            "adminLogCount": admin_log_count,
            "authLogsPresent": auth_logs_present,
            "adminLogsPresent": admin_logs_present
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "authLogCount": auth_log_count,
                "adminLogCount": admin_log_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
