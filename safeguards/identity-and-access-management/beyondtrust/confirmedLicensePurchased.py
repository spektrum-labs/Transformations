"""
Transformation: confirmedLicensePurchased
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: Whether a valid BeyondTrust Password Safe license is active,
verified by a successful (non-error) response from the ManagedAccounts endpoint.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "BeyondTrust", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    """Return True if the ManagedAccounts endpoint responded without a license/auth error."""
    try:
        if data is None:
            return {"confirmedLicensePurchased": False, "reason": "Null response - possible license error"}

        if isinstance(data, dict):
            # An EMPTY dict, or one with none of the recognised signals below, used to
            # fall through "no error keyword found" straight to True -- so {} and every
            # unrecognised body were read as a confirmed license. Resolved from the
            # payload now; see affirmative_signal below.
            if not data:
                return {"confirmedLicensePurchased": False, "reason": "Empty response body"}
            # BeyondTrust surfaces license failures as error dicts with Message/error keys
            error_msg = str(data.get("Message", data.get("error", ""))).lower()
            if "license" in error_msg or "invalid" in error_msg:
                return {"confirmedLicensePurchased": False, "reason": error_msg}
            status_val = str(data.get("status", "")).lower()
            message_val = str(data.get("message", data.get("Message", ""))).lower()
            if status_val == "error" and "authentication failed" in message_val:
                return {"confirmedLicensePurchased": False, "reason": "Authentication failed"}
            return {"confirmedLicensePurchased": affirmative_signal(data)}

        if isinstance(data, list):
            return {"confirmedLicensePurchased": True, "managedAccountCount": len(data)}

        return {"confirmedLicensePurchased": False, "reason": "Unexpected response type"}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Review BeyondTrust configuration for " + criteriaKey)
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])


def affirmative_signal(data):
    """True only when a non-error dict POSITIVELY evidences an active license.

    The caller has already ruled out an empty body and the BeyondTrust-specific error
    shapes (Message/error text naming "license"/"invalid", or an explicit
    status=="error"). This still must not default True for an arbitrary unrecognised
    dict -- a synthetic body describing every control as off (`"enabled": False`,
    `"licensed": False`, ...) is not evidence of a purchased license either.

    Deliberately conservative, in this order:
      * an explicit OFF among the recognised keys    -> False   (beats any other signal)
      * an explicit ON among the recognised keys     -> True
      * a non-empty population of records/settings   -> True
      * anything unrecognised                        -> False  (never True by default)
    """
    on_keys = ("enabled", "isEnabled", "active", "isActive", "configured", "isConfigured",
               "licensed", "licensePurchased", "subscribed", "subscription", "status",
               "state", "installed", "compliant")
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
    for key in ("items", "data", "records", "results", "accounts", "managedAccounts",
                "policies", "settings"):
        value = data.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
    return False
