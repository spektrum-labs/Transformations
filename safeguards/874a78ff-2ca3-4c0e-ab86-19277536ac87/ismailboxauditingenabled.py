"""
Transformation: isMailboxAuditingEnabled
Vendor: Microsoft
Category: Email Security / Secure Score

Evaluates if mailbox auditing is enabled based on Microsoft Secure Score (control exo_mailboxaudit).

A failed call, an empty response or a response without the control is reported as a data-collection error
(additionalInfo.dataCollection.status == "error"), which Token-Service renders Unevaluated, not a measured 0%.
The email-logging criteria are answered by isauditlogsearchenabled.py (mip_search_auditlog), not by this file.
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
        "transformationId": "isMailboxAuditingEnabled",
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


def no_data(criteriaKey, message, recommendation):
    """dataCollection.status "error" -> Token-Service reports the criterion Unevaluated, not 0%."""
    return create_response(
        result={criteriaKey: False},
        validation={"status": "skipped", "errors": [], "warnings": [message]},
        api_errors=[message],
        fail_reasons=[message],
        recommendations=[recommendation]
    )


def transform(input):
    """
    Evaluates if mailbox auditing is enabled based on Microsoft Secure Score.

    Parameters:
        input: Either enriched format {"data": {...}, "validation": {...}}
               or legacy format (raw API response)

    Returns:
        dict: Standardized response with transformedResponse and additionalInfo
    """
    criteriaKey = "isMailboxAuditingEnabled"
    controlName = "exo_mailboxaudit"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if not isinstance(data, dict):
            return no_data(criteriaKey, "Microsoft Secure Score returned no data",
                           "Verify the Microsoft Graph integration is returning Secure Score data")

        if data.get("error") or data.get("statusCode") or data.get("status_code"):
            err = data.get("error")
            if isinstance(err, dict):
                raw = str(err.get("code") or "") + " " + str(err.get("message") or err.get("statusCode") or "")
            else:
                raw = str(err or data.get("statusCode") or data.get("status_code"))
            api_error, recommendation = parse_api_error(raw.strip(), source="Microsoft Graph Secure Score")
            return no_data(criteriaKey, api_error, recommendation)

        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(data.get('PSError', ''), source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve data from Microsoft 365"],
                recommendations=[recommendation]
            )

        if validation.get("status") == "failed":
            return no_data(criteriaKey, "Input validation failed: " + "; ".join(validation.get("errors", [])),
                           "Verify the Microsoft integration is configured correctly")

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        score_in_percentage = 0.0
        count = 0
        total = 0
        is_enabled = False

        # Process Secure Score data
        values = data.get("value")
        if not isinstance(values, list) or len(values) == 0 or not isinstance(values[0], dict):
            return no_data(criteriaKey, "Microsoft Secure Score data not available",
                           "Verify the Microsoft Graph integration is returning Secure Score data")
        if len(values) > 0:
            control_scores = values[0].get("controlScores", [])
            matched_object_list = [i for i in control_scores if i.get('controlName') == controlName]

            if len(matched_object_list) > 1:
                fail_reasons.append(f"Ambiguous data: {len(matched_object_list)} objects match controlName '{controlName}'")
                return create_response(
                    result={criteriaKey: False},
                    validation=validation,
                    fail_reasons=fail_reasons,
                    recommendations=["Check Microsoft Secure Score data for duplicate control entries"]
                )
            elif len(matched_object_list) == 1:
                matched_object = matched_object_list[0]

                score_in_percentage = to_number(matched_object.get("scoreInPercentage"))
                if score_in_percentage is None:
                    return no_data(criteriaKey, f"Secure Score control '{controlName}' has no scoreInPercentage",
                                   "Verify Microsoft Secure Score is scoring the mailbox audit control")
                is_enabled = score_in_percentage >= 100.0

                count = matched_object.get("count", 0)
                total = matched_object.get("total", 0)

                if is_enabled:
                    pass_reasons.append(f"Mailbox auditing is fully enabled (score: 100%)")
                else:
                    fail_reasons.append(f"Mailbox auditing score is {score_in_percentage}% ({count}/{total} mailboxes)")
                    recommendations.append("Enable mailbox auditing for all Exchange Online mailboxes")
            else:
                return no_data(criteriaKey, f"Secure Score data has no '{controlName}' control",
                               "Verify Microsoft Secure Score is collecting mailbox audit data")

        result = {
            criteriaKey: is_enabled,
            "scoreInPercentage": score_in_percentage,
            "count": count,
            "total": total
        }

        input_summary = {
            "hasSecureScoreData": len(values) > 0,
            "scoreInPercentage": score_in_percentage,
            "auditedMailboxes": count,
            "totalMailboxes": total
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )

    except json.JSONDecodeError as e:
        return no_data(criteriaKey, f"Invalid JSON from Microsoft Secure Score: {str(e)}",
                       "Verify the Microsoft Graph integration is returning Secure Score data")
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
