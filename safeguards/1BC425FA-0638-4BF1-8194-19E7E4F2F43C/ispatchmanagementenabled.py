"""
Transformation: isPatchManagementEnabled
Vendor: MDR / Managed Detection and Response
Category: Endpoint Security / Patch Management

Evaluates if patch management is enabled and valid.
"""

import json
from datetime import datetime


def transform(input):
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
                    "transformationId": "isPatchManagementEnabled",
                    "vendor": "MDR Provider",
                    "category": "Endpoint Security"
                }
            }
        }

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isPatchManagementEnabled": False, "isPatchManagementValid": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Default to True if data is present (indicates active integration)
        # `data is not None` asked whether a RESPONSE ARRIVED, not what it said, so any
        # 2xx body -- including one describing the control as OFF -- satisfied this
        # criterion and no input could make it false. Resolved from the payload now.
        default_value = affirmative_signal(data)

        if not default_value and no_endpoints(data, ["isPatchManagementEnabled", "isPatchManagementValid"]):
            return create_response(
                result={"isPatchManagementEnabled": None, "isPatchManagementValid": None},
                validation=validation,
                fail_reasons=[NO_ENDPOINTS_REASON],
                api_errors=[NO_ENDPOINTS_REASON],
                input_summary={"patchManagementEnabled": None, "patchManagementValid": None, "endpointCount": 0}
            )

        is_patch_management_enabled = False
        is_patch_management_valid = False

        if isinstance(data, dict):
            is_patch_management_enabled = data.get('isPatchManagementEnabled', default_value)
            is_patch_management_valid = data.get('isPatchManagementValid', default_value)
            if is_patch_management_valid is None and is_patch_management_enabled is not None:
                # The body states isPatchManagementEnabled but says nothing about isPatchManagementValid. Keep the
                # secondary a fail, as before, rather than a None that would turn the
                # explicit primary verdict into Not evaluated.
                is_patch_management_valid = False
        else:
            is_patch_management_enabled = default_value
            is_patch_management_valid = default_value

        additional_findings = []

        # Primary criteria: isPatchManagementEnabled
        if is_patch_management_enabled:
            pass_reasons.append("Patch management is enabled")
        else:
            fail_reasons.append("Patch management is not enabled")
            recommendations.append("Enable patch management for endpoint security")

        # Additional finding: isPatchManagementValid
        if is_patch_management_valid:
            additional_findings.append({
                "metric": "isPatchManagementValid",
                "status": "pass",
                "reason": "Patch management configuration is valid"
            })
        else:
            additional_findings.append({
                "metric": "isPatchManagementValid",
                "status": "fail",
                "reason": "Patch management configuration is not valid",
                "recommendation": "Review and correct patch management configuration"
            })

        return create_response(
            result={
                "isPatchManagementEnabled": is_patch_management_enabled,
                "isPatchManagementValid": is_patch_management_valid
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "patchManagementEnabled": is_patch_management_enabled,
                "patchManagementValid": is_patch_management_valid
            }
        )

    except Exception as e:
        return create_response(
            result={"isPatchManagementEnabled": False, "isPatchManagementValid": False},
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


NO_ENDPOINTS_REASON = "Not evaluated: no endpoints returned"


def no_endpoints(data, keys):
    """True when the read is an endpoint list with no endpoints in it and no explicit verdict key.

    {"items": [], "pages": {...}} (or a bare []) says there is nothing to measure, not that the
    control is off: per the answer model, no usable data is Not evaluated, never a fail.
    """
    if isinstance(data, list):
        return len(data) == 0
    if not isinstance(data, dict):
        return False
    for key in keys:
        if key in data:
            return False
    items = data.get("items")
    return isinstance(items, list) and len(items) == 0
