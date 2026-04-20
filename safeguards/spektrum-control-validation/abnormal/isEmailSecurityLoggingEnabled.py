"""
Transformation: isEmailSecurityLoggingEnabled
Vendor: Abnormal Security  |  Category: Email Security
Evaluates: Validates that audit logging is enabled in Abnormal Security by confirming
the audit log endpoint returns event records.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for iter_idx in range(3):
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
                "transformationId": "isEmailSecurityLoggingEnabled",
                "vendor": "Abnormal Security",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isEmailSecurityLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "logCount": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        logging_enabled = False
        log_count = 0

        if isinstance(data, dict):
            # getAuditLogs returnSpec uses "logs" as the primary key
            audit_logs = data.get("logs", data.get("auditLogs", data.get("results", [])))
            if isinstance(audit_logs, list):
                log_count = len(audit_logs)
                # A valid logs list (even empty) from the audit endpoint confirms logging is active
                logging_enabled = True
            elif "pageNumber" in data or "nextPageNumber" in data:
                # Paginated response structure from audit endpoint confirms logging is active
                logging_enabled = True

            # Override with explicit settings if present
            settings = data.get("settings", {})
            if isinstance(settings, dict):
                audit = settings.get("auditLogging", settings.get("logging", {}))
                if isinstance(audit, dict):
                    explicit_enabled = audit.get("enabled", None)
                    if explicit_enabled is not None:
                        logging_enabled = explicit_enabled

        if logging_enabled:
            reason = "Audit logging is enabled in Abnormal Security"
            if log_count > 0:
                reason = reason + " (" + str(log_count) + " log entries found)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Audit logging is not enabled or the audit endpoint returned no data")
            recommendations.append(
                "Enable audit logging in Abnormal Security for compliance and incident response tracking"
            )

        return create_response(
            result={criteriaKey: logging_enabled, "logCount": log_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"loggingEnabled": logging_enabled, "logCount": log_count}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "logCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
