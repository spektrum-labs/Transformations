"""
Transformation: isIAMLoggingEnabled
Vendor: Microsoft
Category: Identity / Logging

Input: the Microsoft Graph directory audit read behind the Entra getLoggingInfo method
(getAuditLogging, GET /auditLogs/directoryAudits): {"value": [directoryAudit, ...]}.
See https://learn.microsoft.com/en-us/graph/api/directoryaudit-list

Why this file exists (ENG-1349): isIAMLoggingEnabled was wired to is_mfa_logging_enabled.py,
which only ever writes isMFALoggingEnabled, so the IAM logging check was never graded. This
transform writes its own key.

Verdict policy:
  * True  -- the read returned at least one directory audit record. Records only exist
             when Entra is recording identity and access changes.
  * None  -- every other case, reported as Not evaluated with a plain reason: an
             unreadable body, a Graph error or permission refusal, a body with no record
             list, or an empty list (no records in the window says nothing either way).
  * False -- never. Entra directory audit logging cannot be switched off by the tenant,
             and this read has no on/off setting to report.
"""

import json
from datetime import datetime


CRITERIA_KEY = "isIAMLoggingEnabled"
PERMISSION_CODES = ["Authorization_RequestDenied", "Forbidden", "AccessDenied", "Unauthorized",
                    "InvalidAuthenticationToken"]
EVIDENCE_HINT = ("Grant the integration AuditLog.Read.All with admin consent, or upload evidence "
                 "of Entra directory audit records instead.")


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
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if not isinstance(validation, dict):
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
                "transformationId": CRITERIA_KEY,
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def not_evaluated(reason, validation=None, input_summary=None, transformation_errors=None):
    """Criterion None plus an api_errors entry: the evaluator records it as Not evaluated."""
    return create_response(
        result={CRITERIA_KEY: None},
        validation=validation,
        fail_reasons=[reason],
        recommendations=[EVIDENCE_HINT],
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        api_errors=[reason]
    )


def as_int(value):
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return 0


def error_code(data):
    """The Graph error code from an error body, or "" when the body is not an error."""
    error_info = data.get("error")
    if isinstance(error_info, dict):
        return str(error_info.get("code") or "unknown")
    if error_info:
        return "unknown"
    status = data.get("statusCode", data.get("status_code"))
    if as_int(status) >= 400:
        return "HTTP " + str(as_int(status))
    return ""


def transform(input):
    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(
                "The Microsoft response could not be validated, so IAM logging was not evaluated.",
                validation=validation
            )

        if not isinstance(data, dict):
            return not_evaluated(
                "Microsoft returned no readable response, so IAM logging was not evaluated."
            )

        code = error_code(data)
        if code:
            if code in PERMISSION_CODES or code in ["HTTP 401", "HTTP 403"]:
                reason = ("Microsoft refused the directory audit log request (" + code + "). The app "
                          "registration may be missing AuditLog.Read.All or admin consent, so IAM "
                          "logging was not evaluated.")
            else:
                reason = ("Microsoft returned an error (" + code + ") for the directory audit log "
                          "request, so IAM logging was not evaluated.")
            return not_evaluated(reason, input_summary={"errorCode": code})

        records = data.get("value")
        if not isinstance(records, list):
            return not_evaluated(
                "The Microsoft response did not contain a list of directory audit records, so IAM "
                "logging was not evaluated."
            )

        records = [r for r in records if isinstance(r, dict) and r]
        summary = {"auditRecordCount": len(records)}

        if len(records) == 0:
            return not_evaluated(
                "Microsoft returned no directory audit records for the period read. That does not "
                "show whether identity changes are being logged, so IAM logging was not evaluated.",
                input_summary=summary
            )

        return create_response(
            result={CRITERIA_KEY: True},
            validation=validation,
            pass_reasons=["Entra recorded " + str(len(records))
                          + " directory audit record(s) in the period read, so identity and access "
                            "changes are being logged."],
            input_summary=summary
        )

    except Exception as e:
        return not_evaluated(
            "The Microsoft response could not be read, so IAM logging was not evaluated.",
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)]
        )
