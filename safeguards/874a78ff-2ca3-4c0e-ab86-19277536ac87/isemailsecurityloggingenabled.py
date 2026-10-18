"""
Transformation: isEmailSecurityLoggingEnabled
Vendor: Microsoft
Category: Email Security / Logging

Evaluates if email security logging is enabled.

True when the read returned at least one sign-in entry (an object with at least one field); more pages beyond it
change nothing, and entries that are null, text, numbers, lists or empty objects are not counted.

Not evaluated (every key None, with a collection error) whenever the body does not prove the answer: a vendor
error marker, a body that is not a sign-in list (an error body, an empty or null response), an empty sign-in
list, a list with no readable sign-in entry, malformed or unreadable input, and failed input validation. An empty list proves nothing either way: it is
both a tenant with no retained sign-ins and a read that was not allowed to see them, and the read carries no date
window that would make it a stated "no logs". Nothing here can prove logging is off, so there is no False.
"""

import json
from datetime import datetime

RESULT_KEYS = ("isEmailSecurityLoggingEnabled", "isEmailLoggingEnabled")


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
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
                "transformationId": "isEmailSecurityLoggingEnabled",
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }



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

def not_evaluated(validation, api_error, fail_reason, recommendation, transformation_errors=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={key: None for key in RESULT_KEYS},
        validation=validation,
        transformation_errors=transformation_errors,
        api_errors=[api_error],
        fail_reasons=[fail_reason],
        recommendations=[recommendation]
    )


def transform(input):
    criteriaKey = "isEmailSecurityLoggingEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(
                validation,
                "Could not read the sign-in logs: input validation failed",
                "Input validation failed",
                "Re-evaluate this check once the sign-in log read succeeds"
            )

        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(str(data.get('PSError') or ''), source="Microsoft 365")
            return not_evaluated(
                {"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_error,
                "Could not retrieve data from Microsoft 365",
                recommendation
            )

        # A Graph error body, an empty body or a null value is not a sign-in list, so it proves nothing either way.
        logging_entries = data.get('value') if isinstance(data, dict) else None
        if not isinstance(logging_entries, list):
            return not_evaluated(
                validation,
                "The sign-in log read did not return a list of sign-ins (error body, missing permission or empty response)",
                "No sign-in list was returned, so this check could not be evaluated",
                "Verify the integration can read Microsoft Entra sign-in logs (AuditLog.Read.All), then re-evaluate this check"
            )
        if len(logging_entries) == 0:
            return not_evaluated(
                validation,
                "The sign-in log read returned no sign-ins (empty list)",
                "No sign-in was returned, so this check could not be evaluated",
                "Verify the integration can read Microsoft Entra sign-in logs (AuditLog.Read.All), then re-evaluate this check"
            )

        # Only an object with at least one field is a sign-in entry; null, text, a number, a list or {} proves nothing.
        sign_ins = [entry for entry in logging_entries if isinstance(entry, dict) and len(entry) > 0]
        if len(sign_ins) == 0:
            return not_evaluated(
                validation,
                "The sign-in log read returned no readable sign-in entry (the list holds no object with fields)",
                "No sign-in entry could be read, so this check could not be evaluated",
                "Verify the integration can read Microsoft Entra sign-in logs (AuditLog.Read.All), then re-evaluate this check"
            )

        return create_response(
            result={criteriaKey: True, "isEmailLoggingEnabled": True},
            validation=validation,
            pass_reasons=[f"Email security logging is enabled with {len(sign_ins)} log entries found"],
            input_summary={"logEntryCount": len(sign_ins)}
        )

    except Exception as e:
        message = str(e)[:200]  # the text reaches the stored result, so a long one is cut
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            "Could not evaluate the response",
            f"Transformation error: {message}",
            "Re-evaluate this check once the sign-in log read succeeds",
            transformation_errors=[message]
        )
