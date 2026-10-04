"""
Transformation: confirmedLicensePurchased
Vendor: Qualys (Attack Surface Management)
Category: Security / Licensing

Reads GET /qps/rest/portal/version. Qualys serves the QPS API only to an active
subscription, so ServiceResponse.responseCode SUCCESS proves the licence. A refused,
failed or unrecognised answer is Not evaluated (None), never False by default.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Attack Surface Management",
                "category": "Security"
            }
        }
    }


# The workflow stores the portal call's output under this key; older wiring passed the
# body bare. Both are read.
WORKFLOW_KEYS = ("licenseStatus",)

# Qualys QPS answers every call with ServiceResponse.responseCode. Only these codes say the
# SUBSCRIPTION itself is missing or lapsed, so only these read as "no licence". Qualys
# documents no such QPS code today; they are recognised defensively and stay narrow.
LICENCE_ABSENT_CODES = ("SUBSCRIPTION_EXPIRED", "SUBSCRIPTION_INACTIVE", "LICENSE_EXPIRED",
                        "LICENSE_NOT_FOUND", "NO_SUBSCRIPTION", "SUBSCRIPTION_NOT_FOUND")


def find_service_response(data):
    """Return the QPS ServiceResponse dict, or None when the body carries none."""
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("ServiceResponse"), dict):
        return data["ServiceResponse"]
    for key in WORKFLOW_KEYS:
        inner = data.get(key)
        if isinstance(inner, dict) and isinstance(inner.get("ServiceResponse"), dict):
            return inner["ServiceResponse"]
    return None


def portal_version(service_response):
    payload = service_response.get("data")
    if not isinstance(payload, dict):
        return ""
    version = payload.get("Portal-Version")
    if not isinstance(version, dict):
        return ""
    value = version.get("PortalApplication-VERSION")
    return value if isinstance(value, str) else ""


def is_error_envelope(data):
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors"):
        return True
    message = data.get("message")
    return isinstance(message, str) and message.startswith("Integration execution error")


def not_evaluated(criteriaKey, validation, reason, recommendation=None, api_errors=None):
    """None reads Unevaluated downstream: a call that proved nothing is not a missing licence."""
    return create_response(
        result={criteriaKey: None},
        validation=validation,
        fail_reasons=[reason],
        recommendations=[recommendation] if recommendation else [],
        api_errors=api_errors,
        input_summary={"licensePurchased": None}
    )


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(criteriaKey, validation, "Input validation failed")

        # Legacy shape: an explicit boolean still decides.
        if isinstance(data, dict) and isinstance(data.get("licensePurchased"), bool):
            if data["licensePurchased"]:
                return create_response(
                    result={criteriaKey: True},
                    validation=validation,
                    pass_reasons=["License has been purchased for Attack Surface Management"],
                    input_summary={"licensePurchased": True}
                )
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["License has not been purchased"],
                recommendations=["Purchase license for Attack Surface Management"],
                input_summary={"licensePurchased": False}
            )

        service_response = find_service_response(data)

        if service_response is None:
            if is_error_envelope(data) or (isinstance(data, dict) and is_error_envelope(data.get("licenseStatus"))):
                return not_evaluated(
                    criteriaKey, validation,
                    "Qualys did not answer the portal call; licence not evaluated",
                    "Verify the Qualys API credentials and base URL",
                    api_errors=["Qualys portal call returned an error"]
                )
            # Kept from the previous rule so no body that passed before stops passing: a
            # non-Qualys-shaped body that positively evidences a licence still reads True.
            if affirmative_signal(data):
                return create_response(
                    result={criteriaKey: True},
                    validation=validation,
                    pass_reasons=["License has been purchased for Attack Surface Management"],
                    input_summary={"licensePurchased": True}
                )
            return not_evaluated(criteriaKey, validation,
                                 "No Qualys ServiceResponse in the body; licence not evaluated")

        code = service_response.get("responseCode")
        code = code.strip().upper() if isinstance(code, str) else ""

        if code == "SUCCESS":
            version = portal_version(service_response)
            reason = "Qualys answered the authenticated portal call with SUCCESS"
            if version:
                reason = reason + " (portal " + version + ")"
            return create_response(
                result={criteriaKey: True},
                validation=validation,
                pass_reasons=[reason],
                input_summary={"licensePurchased": True, "responseCode": code}
            )

        if code in LICENCE_ABSENT_CODES:
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Qualys reports the subscription is not active (" + code + ")"],
                recommendations=["Renew or purchase the Qualys subscription"],
                input_summary={"licensePurchased": False, "responseCode": code}
            )

        # Auth, permission, request or unknown codes: the call was refused or failed, which
        # is not evidence that no licence exists.
        return not_evaluated(
            criteriaKey, validation,
            "Qualys returned " + (code or "no responseCode") + "; licence not evaluated",
            "Verify the Qualys API user's credentials and API access permission",
            api_errors=["Qualys responseCode " + (code or "missing")]
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )


def affirmative_signal(data):
    """True only when the payload POSITIVELY evidences the control.

    Replaces `data is not None`, which asked whether a response arrived rather than what
    it said -- so any 2xx body, including one describing the control as OFF, satisfied the
    criterion and no input could ever make it false. Measured 2026-09-21.

    Deliberately conservative, in this order:
      * an unreadable, empty or error body           -> False
      * an explicit OFF among the recognised keys    -> False   (beats any other signal)
      * an explicit ON among the recognised keys     -> True
      * a non-empty population of records/settings   -> True
      * anything unrecognised                        -> False  (never True by default)
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
               "enforced", "isEnforced", "loggingEnabled", "status", "state", "licensed",
               "licensePurchased", "subscribed", "subscription")
    present = [data[k] for k in on_keys if k in data]
    off_words = ("false", "disabled", "off", "inactive", "none", "expired", "cancelled")
    on_words = ("true", "enabled", "on", "active", "success", "ok", "valid", "licensed")
    for value in present:
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
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
    return False
