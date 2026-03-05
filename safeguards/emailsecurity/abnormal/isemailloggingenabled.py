"""
Transformation: isEmailLoggingEnabled
Vendor: Abnormal Security
Category: Email Security / Logging

Checks if email logging/audit trail is enabled in Abnormal Security.
Evaluates audit log presence, paginated responses, and logging configuration.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "isEmailLoggingEnabled",
                "vendor": "Abnormal Security",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isEmailLoggingEnabled"

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
            # Check audit logs response
            audit_logs = data.get('auditLogs', data.get('results', data.get('logs', [])))
            if isinstance(audit_logs, list):
                log_count = len(audit_logs)
                logging_enabled = log_count > 0
            elif 'total_count' in data:
                log_count = data['total_count']
                logging_enabled = log_count > 0
            elif 'pageNumber' in data:
                # Paginated response means logging is active
                logging_enabled = True

            # Check settings for logging configuration
            settings = data.get('settings', {})
            if isinstance(settings, dict):
                audit = settings.get('auditLogging', settings.get('logging', {}))
                if isinstance(audit, dict):
                    logging_enabled = audit.get('enabled', logging_enabled)

        if logging_enabled:
            reason = "Email security logging is enabled"
            if log_count > 0:
                reason += f" ({log_count} log entries found)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Email security logging is not enabled")
            recommendations.append("Enable audit logging in Abnormal Security for compliance tracking")

        return create_response(
            result={criteriaKey: logging_enabled, "logCount": log_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"logCount": log_count, "loggingEnabled": logging_enabled}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "logCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
