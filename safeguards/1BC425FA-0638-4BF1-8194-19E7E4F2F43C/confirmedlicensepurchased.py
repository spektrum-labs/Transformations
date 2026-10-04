"""
Transformation: confirmedLicensePurchased
Vendor: Sophos Central (shared by the Sophos product integrations)
Category: Licensing

Evaluates whether Sophos Central reports a licensed, configured product, from the product
flags the healthCheck read returns: isEPPConfigured, isMDRConfigured and, when present,
isEmailConfigured / isEmailSecurityConfigured / isFirewallConfigured. Each flag may be a
boolean or the string "true" / "false".

  * every recognised product flag is explicitly false  -> False
  * any other product-flag body (including a true flag) -> None (Not evaluated)
  * no recognised flag, empty or error body             -> None (Not evaluated)

The input does not say which Sophos integration row asked, so a true flag cannot prove the
asking product's licence (an Endpoint Protection flag must not pass Firewall): that needs a
per-product licence read (getLicenses). A legacy `licensePurchased` key is still honoured
first, and a body with no product flags keeps the earlier positive reading.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

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
                    "vendor": "Sophos",
                    "category": "Licensing"
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
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        license_purchased, reason, products = sophos_license(data)
        summary = {"licensePurchased": license_purchased, "productFlags": products}

        if license_purchased is None:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=[reason],
                api_errors=[reason],
                input_summary=summary
            )

        if license_purchased:
            pass_reasons.append(reason)
        else:
            fail_reasons.append(reason)
            recommendations.append("Confirm the Sophos Central product licence for this integration is purchased and configured")

        return create_response(
            result={criteriaKey: license_purchased},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
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


NOT_PER_PRODUCT_REASON = ("Sophos healthCheck does not say which product is licensed; "
                          "a per-product licence read (getLicenses) is needed")

PRODUCT_FLAGS = (
    ("isEPPConfigured", "Endpoint Protection"),
    ("isMDRConfigured", "MDR"),
    ("isEmailConfigured", "Email Security"),
    ("isEmailSecurityConfigured", "Email Security"),
    ("isFirewallConfigured", "Firewall"),
)


def flag_value(value):
    """True / False for a boolean or "true" / "false" string, else None."""
    if value is True or value is False:
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
    return None


def sophos_license(data):
    """(True | False | None, reason, {flag: value}) for the Sophos healthCheck body."""
    if not isinstance(data, dict):
        if affirmative_signal(data):
            return True, "Sophos licence confirmed: the read returned a populated product list", {}
        return None, "Not evaluated: the Sophos licence read returned no data", {}
    if "licensePurchased" in data:
        legacy = data.get("licensePurchased")
        if legacy:
            return legacy, "Sophos licence confirmed (licensePurchased: true)", {}
        return legacy, "Sophos licence not purchased (licensePurchased: false)", {}

    products = {}
    licensed = []
    unlicensed = []
    for key, label in PRODUCT_FLAGS:
        if key not in data:
            continue
        value = flag_value(data.get(key))
        products[key] = value
        if value is True and label not in licensed:
            licensed.append(label)
        elif value is False and label not in unlicensed:
            unlicensed.append(label)

    if products and all(v is False for v in products.values()):
        return False, "Sophos Central reports no configured product: " + ", ".join(unlicensed) + " not configured", products
    if products:
        # A true flag names a Sophos product, but the input does not say which product row is
        # asking: an Endpoint Protection flag must not pass a Firewall or Email Security licence.
        return None, NOT_PER_PRODUCT_REASON, products

    if affirmative_signal(data):
        return True, "Sophos licence confirmed: the read returned an active licence signal", products
    return None, "Not evaluated: the Sophos licence read returned no product flags", products
