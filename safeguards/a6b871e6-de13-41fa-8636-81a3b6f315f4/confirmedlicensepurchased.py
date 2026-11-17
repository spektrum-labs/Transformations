"""
Transformation: confirmedLicensePurchased
Vendor: Qualys (Attack Surface Management)
Category: Security / Licensing

Reads GET /qps/rest/portal/version. A ServiceResponse.responseCode of SUCCESS shows that the
API user authenticated and the portal answered; it carries no subscription, module or expiry
field, and Qualys lists a product subscription as Active, Trial or Expired, so SUCCESS does not
tell a purchase from a trial. SUCCESS is therefore Not evaluated (None), not a pass. A code that
names an expired or missing subscription is False; an explicit licensePurchased flag still
decides. A refused, failed or unrecognised answer is Not evaluated, never False by default.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('confirmedLicensePurchased',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
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
            # Reachability, not a licence: the portal version answers any authenticated API user.
            version = portal_version(service_response)
            reason = "Qualys answered the authenticated portal call (SUCCESS"
            reason = reason + (", portal " + version + ")" if version else ")")
            return not_evaluated(
                criteriaKey, validation,
                reason + ", which shows the API user can sign in, not that a subscription was purchased",
                "Wire a Qualys read that returns the subscription's status (Active, Trial, Expired) to prove the licence",
                api_errors=["The portal version call carries no subscription evidence"]
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
