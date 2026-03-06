"""
Transformation: isEmailLoggingEnabled
Vendor: Mimecast
Category: Email Security / Logging

Ensures email security logs are integrated with SIEM.
Checks logging status, audit log presence, and state/status indicators.
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
                "vendor": "Mimecast",
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
        logging_state = ''

        if isinstance(data, dict):
            if 'loggingEnabled' in data or 'auditEnabled' in data:
                logging_enabled = bool(data.get('loggingEnabled', data.get('auditEnabled', False)))
            elif 'enabled' in data:
                logging_enabled = bool(data['enabled'])
            elif 'state' in data or 'status' in data:
                logging_state = str(data.get('state', data.get('status', ''))).lower()
                logging_enabled = logging_state in ['enabled', 'active', 'on']
            elif 'logs' in data:
                logs = data['logs'] if isinstance(data['logs'], list) else []
                log_count = len(logs)
                logging_enabled = log_count > 0
            elif 'auditLog' in data:
                logging_enabled = bool(data['auditLog'])

        if logging_enabled:
            reason = "Email security logging is enabled"
            if log_count > 0:
                reason += f" ({log_count} log entries found)"
            elif logging_state:
                reason += f" (state: {logging_state})"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Email security logging is not enabled")
            recommendations.append("Enable email security logging and SIEM integration in Mimecast")

        return create_response(
            result={criteriaKey: logging_enabled, "logCount": log_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"logCount": log_count, "loggingEnabled": logging_enabled, "state": logging_state}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "logCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
