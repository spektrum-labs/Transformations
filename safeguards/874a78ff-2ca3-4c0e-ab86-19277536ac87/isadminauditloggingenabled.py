"""
Transformation: isAdminAuditLoggingEnabled
Vendor: Microsoft
Category: Email Security / Logging

Evaluates if admin audit logging is enabled by inspecting the directory audit
log records returned from Microsoft Graph (getDirectoryAuditLogs ->
/auditLogs/directoryAudits). If audit records exist, admin audit logging is
considered enabled.
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
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

    return data, {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
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
                "transformationId": "isAdminAuditLoggingEnabled",
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    """
    Evaluates if admin audit logging is enabled based on directory audit logs.

    Parameters:
        input: Either enriched format {"data": {...}, "validation": {...}}
               or legacy format (raw API response from getDirectoryAuditLogs)

    Returns:
        dict: Standardized response with transformedResponse and additionalInfo
    """
    criteriaKey = "isAdminAuditLoggingEnabled"

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
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))],
                recommendations=["Verify the Microsoft integration is configured correctly"]
            )

        # Check for Microsoft Graph API error response (e.g., 401/403 from missing permissions)
        if isinstance(data, dict) and 'error' in data:
            error_info = data.get('error', {}) or {}
            inner_error = error_info.get('innerError', {}) or {}
            return create_response(
                result={criteriaKey: False},
                validation={"status": "error", "errors": [error_info.get('message', 'API error')], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                recommendations=["Verify AuditLog.Read.All permission is granted with admin consent"],
                input_summary={"errorCode": error_info.get('code'),
                               "innerErrorCode": inner_error.get('code') if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        audit_logs = data.get('value', []) if isinstance(data, dict) else []
        if not isinstance(audit_logs, list):
            audit_logs = [audit_logs] if audit_logs else []

        is_enabled = len(audit_logs) > 0

        if is_enabled:
            pass_reasons.append(f"Admin audit logging is enabled with {len(audit_logs)} audit log entries found")
        else:
            fail_reasons.append("Admin audit logging not enabled or no recent audit entries found")
            recommendations.append("Enable admin audit logging in Exchange Online / Microsoft Purview")

        return create_response(
            result={criteriaKey: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"logCount": len(audit_logs)}
        )

    except json.JSONDecodeError as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [f"Invalid JSON: {str(e)}"], "warnings": []},
            fail_reasons=["Could not parse input as valid JSON"]
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
