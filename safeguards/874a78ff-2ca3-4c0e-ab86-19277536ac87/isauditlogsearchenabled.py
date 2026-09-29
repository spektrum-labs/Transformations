"""
Transformation: isAuditLogSearchEnabled (answers isEmailLoggingEnabled, isEmailSecurityLoggingEnabled)
Vendor: Microsoft
Category: Email Security / Secure Score

Passes when Microsoft Secure Score control mip_search_auditlog ("Turn on audit log search", Microsoft Purview)
is at 100%: the tenant's unified audit log is recording user and admin activity and it can be searched.

Input: GET https://graph.microsoft.com/v1.0/security/secureScores?$top=1 (method getRecentSecureScores).

A failed call, an empty response or a response without the control is reported as a data-collection error
(additionalInfo.dataCollection.status == "error"), which Token-Service renders Unevaluated. "No data" is
never reported as a measured 0%.
"""

import json
from datetime import datetime


# ============================================================================
# Response Helpers (inline for RestrictedPython compatibility)
# ============================================================================

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

    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None, transformation_errors=None, api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "1.0",
        "transformationId": "isAuditLogSearchEnabled",
        "vendor": "Microsoft",
        "category": "Email Security"
    }
    if metadata:
        response_metadata.update(metadata)

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
            "metadata": response_metadata
        }
    }


# ============================================================================
# Transformation Logic
# ============================================================================


def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse raw API error into clean message with source."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '404' in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    elif '429' in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    elif 'connection' in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

def to_number(value):
    """Secure Score numbers arrive as numbers or as strings ("100.0"); anything else is None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def transform(input):
    """
    Evaluates whether Microsoft 365 audit log search (unified audit log) is enabled, from Secure Score.

    Returns isAuditLogSearchEnabled plus the two email-logging criteria wired to this file.
    """
    criteriaKey = "isAuditLogSearchEnabled"
    answeredKeys = ["isEmailLoggingEnabled", "isEmailSecurityLoggingEnabled"]
    controlName = "mip_search_auditlog"

    def verdict(value, extra=None):
        out = {criteriaKey: value}
        for k in answeredKeys:
            out[k] = value
        if extra:
            out.update(extra)
        return out

    def no_data(message, recommendation):
        # dataCollection.status "error" -> Token-Service reports the criterion Unevaluated, not 0%.
        return create_response(
            result=verdict(False),
            validation={"status": "skipped", "errors": [], "warnings": [message]},
            api_errors=[message],
            fail_reasons=[message],
            recommendations=[recommendation]
        )

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if not isinstance(data, dict):
            return no_data("Microsoft Secure Score returned no data",
                           "Verify the Microsoft Graph integration can read Secure Score (SecurityEvents.Read.All)")

        if 'PSError' in data:
            api_error, recommendation = parse_api_error(str(data.get('PSError', '')), source="Microsoft 365")
            return no_data(api_error, recommendation)

        if data.get("error") or data.get("statusCode") or data.get("status_code"):
            err = data.get("error")
            if isinstance(err, dict):
                raw = str(err.get("code") or "") + " " + str(err.get("message") or err.get("statusCode") or "")
            else:
                raw = str(err or data.get("statusCode") or data.get("status_code"))
            api_error, recommendation = parse_api_error(raw.strip(), source="Microsoft Graph Secure Score")
            return no_data(api_error, recommendation)

        if validation.get("status") == "failed":
            return no_data("Input validation failed: " + "; ".join(validation.get("errors", [])),
                           "Verify the Microsoft integration is configured correctly")

        values = data.get("value")
        if not isinstance(values, list) or len(values) == 0 or not isinstance(values[0], dict):
            return no_data("Microsoft Secure Score data not available",
                           "Verify the Microsoft Graph integration is returning Secure Score data")

        control_scores = values[0].get("controlScores")
        if not isinstance(control_scores, list):
            control_scores = []
        matched = [c for c in control_scores if isinstance(c, dict) and c.get("controlName") == controlName]

        if len(matched) == 0:
            return no_data(f"Secure Score data has no '{controlName}' control",
                           "Verify Microsoft Secure Score lists the audit log search control for this tenant")

        if len(matched) > 1:
            return create_response(
                result=verdict(False),
                validation=validation,
                fail_reasons=[f"Ambiguous data: {len(matched)} objects match controlName '{controlName}'"],
                recommendations=["Check Microsoft Secure Score data for duplicate control entries"]
            )

        control = matched[0]
        score_in_percentage = to_number(control.get("scoreInPercentage"))
        if score_in_percentage is None:
            return no_data(f"Secure Score control '{controlName}' has no scoreInPercentage",
                           "Verify Microsoft Secure Score is scoring the audit log search control")

        status_text = str(control.get("implementationStatus") or "")
        last_synced = control.get("lastSynced")
        is_enabled = score_in_percentage >= 100.0

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_enabled:
            pass_reasons.append(f"Microsoft 365 audit log search is enabled (Secure Score {controlName}: 100%). {status_text}".strip())
        else:
            fail_reasons.append(f"Microsoft 365 audit log search is not enabled (Secure Score {controlName}: {score_in_percentage}%). {status_text}".strip())
            recommendations.append("Turn on audit log search (unified audit log) in the Microsoft Purview portal")

        return create_response(
            result=verdict(is_enabled, {"scoreInPercentage": score_in_percentage}),
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "controlName": controlName,
                "scoreInPercentage": score_in_percentage,
                "implementationStatus": status_text,
                "lastSynced": last_synced
            }
        )

    except json.JSONDecodeError as e:
        return no_data(f"Invalid JSON from Microsoft Secure Score: {str(e)}",
                       "Verify the Microsoft Graph integration is returning Secure Score data")
    except Exception as e:
        return create_response(
            result=verdict(False),
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
