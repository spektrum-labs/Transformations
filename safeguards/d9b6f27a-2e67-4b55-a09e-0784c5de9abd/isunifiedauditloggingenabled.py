"""
Transformation: isUnifiedAuditLoggingEnabled
Vendor: Microsoft
Category: Security / Logging

Evaluates if unified audit logging is enabled by checking for audit log entries.
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isUnifiedAuditLoggingEnabled",
                "vendor": "Microsoft",
                "category": "Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isUnifiedAuditLoggingEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "isUnifiedAuditLogEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Check for API error response
        if 'error' in data:
            error_info = data.get('error', {})
            inner_error = error_info.get('innerError', {})
            return create_response(
                result={criteriaKey: False, "isUnifiedAuditLogEnabled": False},
                validation={"status": "error", "errors": [error_info.get('message', 'API error')], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={
                    "errorCode": error_info.get('code'),
                    "innerErrorCode": inner_error.get('code') if inner_error else None
                }
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Ensure value is type list, replace None if found
        value = data.get('value', [])
        if not isinstance(value, list):
            if value is None:
                value = []
            else:
                value = [data.get('value')]

        is_enabled = len(value) > 0

        if is_enabled:
            pass_reasons.append(f"Unified audit logging is enabled with {len(value)} audit log entry(ies) found")
        else:
            fail_reasons.append("No unified audit log entries found")
            recommendations.append("Enable unified audit logging in Microsoft 365 compliance center")

        return create_response(
            result={criteriaKey: is_enabled, "isUnifiedAuditLogEnabled": is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"auditLogEntries": len(value)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "isUnifiedAuditLogEnabled": False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
