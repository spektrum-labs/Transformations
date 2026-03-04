"""
Transformation: isAuditLoggingEnabled
Vendor: Zscaler ZIA
Category: SASE / Logging

Evaluates if admin audit logging is enabled in Zscaler ZIA.
Checks for the presence of audit logs and logging configuration.
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
                "transformationId": "isAuditLoggingEnabled",
                "vendor": "Zscaler ZIA",
                "category": "SASE"
            }
        }
    }


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
                result={criteriaKey: False, "logsCount": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        isAuditLoggingEnabled = False
        logs_count = 0

        if isinstance(data, dict):
            # Get audit logs from response
            audit_logs = data.get('auditLogs', data.get('responseData', []))

            if isinstance(audit_logs, list):
                logs_count = len(audit_logs)
                if logs_count > 0:
                    isAuditLoggingEnabled = True

            # Check for explicit logging status
            if data.get('auditLoggingEnabled', False):
                isAuditLoggingEnabled = True

            if data.get('loggingEnabled', False):
                isAuditLoggingEnabled = True

            # Check for logging configuration
            logging_config = data.get('loggingConfig', data.get('auditConfig', {}))
            if isinstance(logging_config, dict) and logging_config.get('enabled', False):
                isAuditLoggingEnabled = True

            # If we successfully retrieved audit log data, logging is enabled
            if 'apiResponse' in data and data.get('apiResponse'):
                isAuditLoggingEnabled = True

        if isAuditLoggingEnabled:
            pass_reasons.append(f"Audit logging is enabled ({logs_count} log entries found)")
        else:
            fail_reasons.append("Audit logging is not enabled or no audit logs found")
            recommendations.append("Enable admin audit logging in Zscaler ZIA for compliance tracking")

        return create_response(
            result={criteriaKey: isAuditLoggingEnabled, "logsCount": logs_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"logsCount": logs_count, "loggingEnabled": isAuditLoggingEnabled}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "logsCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
