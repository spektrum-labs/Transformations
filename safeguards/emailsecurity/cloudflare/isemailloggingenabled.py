"""
Transformation: isEmailLoggingEnabled
Vendor: Cloudflare Email Security (formerly Area 1)
Category: Email Security / Logging

Checks if email security logging is enabled in Cloudflare Email Security.
Evaluates the investigate endpoint response to confirm that email detections
and events are being captured and logged.
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
                "vendor": "Cloudflare Email Security",
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
            # Cloudflare investigate endpoint returns email events
            messages = data.get('result', data.get('results', data.get('messages', [])))
            result_info = data.get('result_info', {})

            if isinstance(messages, list):
                log_count = len(messages)
                # If the investigate endpoint returns data, logging is active
                logging_enabled = True
            elif isinstance(result_info, dict) and 'total_count' in result_info:
                log_count = result_info.get('total_count', 0)
                logging_enabled = True

            # Check success flag
            if not logging_enabled and data.get('success') is True:
                logging_enabled = True

            # Check audit logs or events lists
            audit_logs = data.get('auditLogs', data.get('logs', data.get('events', [])))
            if isinstance(audit_logs, list) and len(audit_logs) > 0:
                log_count = max(log_count, len(audit_logs))
                logging_enabled = True

        if logging_enabled:
            reason = "Email security logging is enabled"
            if log_count > 0:
                reason += f" ({log_count} email events captured)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Email security logging is not enabled or not returning events")
            recommendations.append("Verify Cloudflare Email Security is properly configured and processing email traffic")

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
