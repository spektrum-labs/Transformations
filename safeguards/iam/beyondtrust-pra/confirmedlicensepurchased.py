"""
Transformation: confirmedLicensePurchased
Vendor: BeyondTrust Privileged Remote Access (PRA)  |  Category: Identity & Access Management
Evaluates: an active PRA license, from evidence in the body only.
PRA's configuration API has no licence endpoint, and the vault account list this check reads
(/api/config/v1/vault/account) shows only that the appliance answered an authenticated call.
A list of vault accounts, empty or not, is therefore Not evaluated (None), never a pass; an
explicit licence field in the body still decides, and a licence error still fails.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "BeyondTrust PRA", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    try:
        if data is None:
            return {"confirmedLicensePurchased": False, "reason": "Null response — possible license or connectivity error"}

        # Error payload detection
        if isinstance(data, dict):
            # An EMPTY dict, or one with none of the recognised signals below, used to
            # fall through "no error keyword found" straight to True -- so {} and every
            # unrecognised body were read as a confirmed license. Resolved from the
            # payload now; see affirmative_signal below.
            if not data:
                return {"confirmedLicensePurchased": False, "reason": "Empty response body"}
            error_msg = str(data.get("error", data.get("message", data.get("detail", "")))).lower()
            if error_msg and any(k in error_msg for k in ("license", "unauthorized", "forbidden", "invalid_client", "invalid_token")):
                return {"confirmedLicensePurchased": False, "reason": error_msg}
            # Dict returned — valid but unexpected shape for vault/account (PRA returns a list)
            return {"confirmedLicensePurchased": affirmative_signal(data)}

        # A vault account list (even empty) shows the appliance answered, not that it is licensed.
        if isinstance(data, list):
            return {"confirmedLicensePurchased": None, "vaultAccountCount": len(data)}

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

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify PRA appliance is licensed, reachable, and API credentials are valid")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
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

    The caller has already ruled out an empty body and the PRA-specific error shapes
    (error/message/detail text naming "license", "unauthorized", etc). This still must
    not default True for an arbitrary unrecognised dict -- a synthetic body describing
    every control as off (`"enabled": False`, `"licensed": False`, ...) is not evidence
    of a purchased license either.

    A generic `status` or `state`, an HTTP code or a populated list shows only that the call
    succeeded, so it can veto but never assert. Measured 2026-11-17: this helper returned True
    for {"status": "ok"}, {"status": 200} and any non-empty list, including the stub the
    evaluation service substitutes for an empty or non-JSON 2xx body ({"status": "Success"}).

    In this order:
      * an explicit OFF, in a setting key or in status/state  -> False   (beats any other signal)
      * an explicit ON in a setting key                       -> True
      * an empty collection                                   -> False
      * anything else                                         -> None    (Not evaluated)
    """
    on_keys = ("enabled", "isEnabled", "active", "isActive", "configured", "isConfigured",
               "licensed", "licensePurchased", "subscribed", "subscription", "installed",
               "compliant")
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
    for key in ("items", "data", "records", "results", "accounts", "vaultAccounts",
                "policies", "settings"):
        value = data.get(key)
        if isinstance(value, (list, dict)) and not value:
            return False
    return None
