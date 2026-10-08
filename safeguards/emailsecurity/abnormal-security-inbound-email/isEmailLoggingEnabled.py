"""
Transformation: isEmailLoggingEnabled
Vendor: Abnormal Security Inbound Email
Method: listAuditLogs  (GET {serverUrl}/v1/auditlogs)

True only when the Abnormal Portal audit log is readable and holds at least one entry:
the response carries an "auditLogs" list with at least one record that has a timestamp
(each record names the user, category, action, status and source IP). The endpoint returns
the last 90 days by default. An error envelope (401/403), an empty body or an unrelated payload
fails closed (False). A readable but EMPTY auditLogs list proves nothing either way, so the
answer is None with a dataCollection error (Not evaluated), never False.

What this proves: Abnormal records portal activity (searches, message views, remediations,
sign-ins) and exposes it through its API. What it does not prove: that logs are exported to
a SIEM or retained beyond the API window.
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, str):
        input_data = json.loads(input_data)
    elif isinstance(input_data, bytes):
        input_data = json.loads(input_data.decode("utf-8"))
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": "isEmailLoggingEnabled",
                "vendor": "Abnormal Security Inbound Email",
                "category": "emailsecurity",
            },
        },
    }


def transform(input):
    criteriaKey = "isEmailLoggingEnabled"
    try:
        data, validation = extract_input(input)
        entries = data.get("auditLogs") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            entries = []

        stamped = 0
        categories = []
        for entry in entries:
            stamp = entry.get("timestamp") if isinstance(entry, dict) else None
            if isinstance(stamp, str) and stamp.strip() not in ("", "None", "null"):
                stamped += 1
                category = entry.get("category")
                if category and category not in categories and len(categories) < 10:
                    categories.append(category)

        enabled = stamped > 0
        if not enabled and isinstance(data, dict) and isinstance(data.get("auditLogs"), list) and not data["auditLogs"]:
            reason = ("GET /v1/auditlogs returned an empty auditLogs list for the 90-day window; "
                      "that does not show whether audit logging is on, so the check is not evaluated.")
            return create_response(
                result={criteriaKey: None, "auditLogRecordsOnPage": 0},
                validation=validation,
                api_errors=[reason],
                fail_reasons=[reason],
                input_summary={"auditLogRecordsOnPage": 0},
            )

        if enabled:
            pass_reasons = [
                "GET /v1/auditlogs returned %d timestamped audit record(s) on this page; Abnormal is "
                "recording portal activity and exposing it through the API." % stamped
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                "GET /v1/auditlogs returned no timestamped audit records (empty list, error or missing "
                "auditLogs), so audit logging is not confirmed."
            ]
            recommendations = [
                "Confirm the REST API token has the Audit Logs read box ticked and that the portal has "
                "recorded activity in the last 90 days."
            ]

        return create_response(
            result={criteriaKey: enabled, "auditLogRecordsOnPage": stamped},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"auditLogRecordsOnPage": stamped, "categoriesObserved": categories},
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)],
        )
