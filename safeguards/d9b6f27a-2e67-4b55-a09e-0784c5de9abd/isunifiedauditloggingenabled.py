"""
Transformation: isUnifiedAuditLoggingEnabled
Vendor: Microsoft
Category: Security / Logging

Input: the Microsoft Graph response to
    GET https://graph.microsoft.com/beta/security/auditLog/queries?$top=1
(Integration-Service ms365 definitions, method getUnifiedAuditLogging).

What that endpoint returns: a list of auditLogQuery objects, the audit log SEARCHES that
someone has created through the Purview Audit Search API. It does not return audit records,
and it has no "unified audit logging is on/off" field. See
https://learn.microsoft.com/en-us/graph/api/security-auditcoreroot-list-auditlogqueries?view=graph-rest-beta
and https://learn.microsoft.com/en-us/graph/api/resources/security-auditlogquery?view=graph-rest-beta

Verdict policy (ENG-1291):
  * True  -- only when a listed search finished ("succeeded"), returned records
             (approximateReturnedRecordCount > 0), and covered a window that ended in the
             last RECENT_DAYS days. Records only exist when the tenant is recording.
  * None  -- every other case, reported as Not evaluated with a plain reason:
             an empty list (nobody has run a search, which says nothing about logging),
             a Graph error or permission refusal, an unexpected body, or searches that
             found nothing recent.
  * False -- never. This endpoint cannot show that logging is off. The setting itself
             (UnifiedAuditLogIngestionEnabled) is read by Exchange Online PowerShell
             Get-AdminAuditLogConfig, which Graph does not expose.
"""

import json
from datetime import datetime, timedelta


CRITERIA_KEY = "isUnifiedAuditLoggingEnabled"
ALIAS_KEY = "isUnifiedAuditLogEnabled"
RECENT_DAYS = 90
PERMISSION_CODES = ["Authorization_RequestDenied", "Forbidden", "AccessDenied", "Unauthorized",
                    "InvalidAuthenticationToken"]
EVIDENCE_HINT = ("Upload evidence instead, for example Exchange Online PowerShell "
                 "Get-AdminAuditLogConfig output showing UnifiedAuditLogIngestionEnabled = True.")


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
                "transformationId": "isUnifiedAuditLoggingEnabled",
                "vendor": "Microsoft",
                "category": "Security"
            }
        }
    }


def verdict(value):
    return {CRITERIA_KEY: value, ALIAS_KEY: value}


def not_evaluated(reason, validation=None, input_summary=None, transformation_errors=None):
    """Criterion None plus an api_errors entry: the evaluator records it as Not evaluated."""
    return create_response(
        result=verdict(None),
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


def recent_record_queries(queries, cutoff_day):
    """Searches that finished, returned records, and covered a window ending on/after cutoff_day."""
    found = []
    for query in queries:
        if not isinstance(query, dict):
            continue
        if str(query.get("status") or "").lower() != "succeeded":
            continue
        if as_int(query.get("approximateReturnedRecordCount")) <= 0:
            continue
        end_day = str(query.get("filterEndDateTime") or "")[:10]
        if len(end_day) != 10 or end_day < cutoff_day:
            continue
        found.append({
            "displayName": str(query.get("displayName") or ""),
            "filterEndDate": end_day,
            "approximateReturnedRecordCount": as_int(query.get("approximateReturnedRecordCount"))
        })
    return found


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(
                "The Microsoft response could not be validated, so Unified Audit Logging was not evaluated.",
                validation=validation
            )

        if not isinstance(data, dict):
            return not_evaluated(
                "Microsoft returned no readable response, so Unified Audit Logging was not evaluated."
            )

        code = error_code(data)
        if code:
            if code in PERMISSION_CODES or code in ["HTTP 401", "HTTP 403"]:
                reason = ("Microsoft refused the audit log request (" + code + "). The app registration "
                          "may be missing the AuditLogsQuery.Read.All permission or admin consent, so "
                          "Unified Audit Logging was not evaluated.")
            else:
                reason = ("Microsoft returned an error (" + code + ") for the audit log request, so "
                          "Unified Audit Logging was not evaluated.")
            return not_evaluated(reason, input_summary={"errorCode": code})

        if "value" not in data or not isinstance(data.get("value"), list):
            return not_evaluated(
                "The Microsoft response did not contain a list of audit log searches, so Unified "
                "Audit Logging was not evaluated."
            )

        queries = data.get("value")
        summary = {"auditLogSearchesListed": len(queries)}

        if len(queries) == 0:
            return not_evaluated(
                "Microsoft returned no saved audit log searches for this tenant. That list shows "
                "searches someone has run, not whether Unified Audit Logging is on, so this check "
                "can't tell either way.",
                input_summary=summary
            )

        cutoff_day = (datetime.utcnow() - timedelta(days=RECENT_DAYS)).date().isoformat()
        evidence = recent_record_queries(queries, cutoff_day)
        summary["searchesWithRecentRecords"] = len(evidence)

        if len(evidence) == 0:
            return not_evaluated(
                "Microsoft listed audit log searches, but none finished with records from the last "
                + str(RECENT_DAYS) + " days, so Unified Audit Logging was not evaluated.",
                input_summary=summary
            )

        best = evidence[0]
        return create_response(
            result=verdict(True),
            validation=validation,
            pass_reasons=[
                "A Microsoft audit log search returned about "
                + str(best["approximateReturnedRecordCount"])
                + " records for a window ending " + best["filterEndDate"]
                + ", so Unified Audit Logging is recording."
            ],
            input_summary=summary,
            additional_findings=evidence
        )

    except Exception as e:
        return not_evaluated(
            "The audit log response could not be read, so Unified Audit Logging was not evaluated.",
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)]
        )
