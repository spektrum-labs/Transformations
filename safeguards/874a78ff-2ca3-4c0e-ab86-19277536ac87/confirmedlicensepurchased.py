"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft
Category: Licensing

Evaluates if the required license has been purchased for the integration.
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
    if not api_errors and None in result.values():
        # A criterion left as None was not measured; say so where the evaluator reads it.
        api_errors = [NOT_EVIDENCED_REASON]
        fail_reasons = [NOT_EVIDENCED_REASON]
        recommendations = []
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Microsoft",
                "category": "Licensing"
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

def transform(input):
    criteriaKey = "confirmedLicensePurchased"

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
                fail_reasons=["Input validation failed"]
            )


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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Default to True if data exists, as presence indicates license
        # `data is not None` asked whether a RESPONSE ARRIVED, not what it said, so any
        # 2xx body -- including one describing the control as OFF -- satisfied this
        # criterion and no input could make it false. Resolved from the payload now.
        default_value = affirmative_signal(data)
        is_purchased = data.get('licensePurchased', default_value)

        if is_purchased:
            pass_reasons.append("Required license active and confirmed")
        else:
            fail_reasons.append("Required license has not been purchased or confirmed")
            recommendations.append("Purchase and configure the required Microsoft 365 license")

        return create_response(
            result={criteriaKey: is_purchased},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"licensePurchased": is_purchased}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )


NOT_EVIDENCED_REASON = (
    "Not evaluated: the response carries no evidence for this criterion. A status field, an "
    "HTTP code or a list of records on its own only shows that the call succeeded."
)


def affirmative_signal(data):
    """What the payload says about this criterion: True, False, or None when it does not say.

    Replaces `data is not None`, which asked whether a response arrived rather than what
    it said -- so any 2xx body, including one describing the control as OFF, satisfied the
    criterion and no input could ever make it false. Measured 2026-09-21.

    A generic `status` or `state`, an HTTP code or a populated list shows only that the call
    succeeded, so it can veto but never assert. Measured 2026-11-17: this helper returned True
    for {"status": "ok"}, {"status": 200} and any non-empty list, including the stub the
    evaluation service substitutes for an empty or non-JSON 2xx body ({"status": "Success"}).

    In this order:
      * an unreadable, empty or error body                    -> False
      * an explicit OFF, in a setting key or in status/state  -> False   (beats any other signal)
      * an explicit ON in a setting key                       -> True
      * an empty collection                                   -> False
      * anything else                                         -> None    (Not evaluated)
    """
    if isinstance(data, list):
        # A top-level JSON array is a population of records, as {"items": [...]} already is,
        # unless an element is an error object (Okta answers errors as {"errorCode": ...}).
        for item in data:
            if isinstance(item, dict) and (item.get("error") or item.get("errors") or item.get("errorCode") or item.get("errorSummary") or item.get("errorMessage")):
                return False
        data = {"items": [item for item in data if item]}
    if not isinstance(data, dict) or not data:
        return False
    for key in ("error", "errors", "errorMessage", "errorType", "fault", "PSError"):
        if data.get(key):
            return False
    on_keys = ("enabled", "isEnabled", "active", "isActive", "configured", "isConfigured",
               "enforced", "isEnforced", "loggingEnabled", "licensed", "licensePurchased",
               "subscribed", "subscription")
    present = [data[k] for k in on_keys if k in data]
    # `status` and `state` describe the call as often as the control: they may veto, never assert.
    reported = present + [data[k] for k in ("status", "state") if k in data]
    off_words = ("false", "disabled", "off", "inactive", "none", "expired", "cancelled")
    on_words = ("true", "enabled", "on", "active", "success", "ok", "valid", "licensed")
    for value in reported:
        if value is False:
            return False
        if isinstance(value, str) and value.strip().lower() in off_words:
            return False
    for value in present:
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in on_words:
            return True
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return True
    for key in ("value", "items", "data", "records", "results", "logs", "events", "policies",
                "settings", "configurations", "devices", "agents", "users", "licenses"):
        value = data.get(key)
        if isinstance(value, (list, dict)) and not value:
            return False
    return None
