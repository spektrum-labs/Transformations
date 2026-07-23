"""
Transformation: isIAMLoggingEnabled
Vendor: Microsoft
Category: Identity / Audit Logging

Evaluates if identity audit logging is active by checking for directory audit log entries.
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
                "transformationId": "isIAMLoggingEnabled",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isIAMLoggingEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if not isinstance(data, dict):
            return create_response(
                result={criteriaKey: False, "auditRecordCount": 0},
                validation=validation,
                fail_reasons=["Unexpected input format: expected a JSON object"]
            )

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "auditRecordCount": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        if "error" in data:
            error_info = data.get("error", {})
            inner_error = error_info.get("innerError", {})
            return create_response(
                result={criteriaKey: False, "auditRecordCount": 0},
                validation={"status": "error", "errors": [error_info.get("message", "API error")], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={"errorCode": error_info.get("code"), "innerErrorCode": inner_error.get("code") if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # An empty value array can reflect a short lookback window even when logging is on;
        # collection-count semantics are accepted house behavior for this feed.
        audit_records = data.get("value") or []
        if not isinstance(audit_records, list):
            audit_records = [audit_records] if audit_records else []

        is_enabled = len(audit_records) > 0

        if is_enabled:
            pass_reasons.append(f"Directory audit logging is active with {len(audit_records)} recent record(s)")
        else:
            fail_reasons.append("No directory audit log records found")
            recommendations.append("Enable directory audit logging in Microsoft Entra ID")

        return create_response(
            result={criteriaKey: is_enabled, "auditRecordCount": len(audit_records)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"auditRecordCount": len(audit_records)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "auditRecordCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
