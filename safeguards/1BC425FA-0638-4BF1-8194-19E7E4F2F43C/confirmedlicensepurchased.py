"""
Transformation: confirmedLicensePurchased
Vendor: Sophos Central (shared by the Sophos product integrations)
Category: Licensing

Evaluates whether Sophos Central reports a licensed, configured product. Only two things in
the body count as licence evidence:

  * a `licensePurchased` key holding true / false (boolean or the string "true" / "false")
  * the Sophos healthCheck product flags: isEPPConfigured, isMDRConfigured and, when present,
    isEmailConfigured / isEmailSecurityConfigured / isFirewallConfigured

  licensePurchased true                                  -> True
  licensePurchased false                                 -> False
  every recognised product flag is explicitly false      -> False
  any other product-flag body (including a true flag)    -> None (Not evaluated)
  anything else                                          -> None (Not evaluated)

"Anything else" includes a generic `status` ("ok", "success", 200), an HTTP code, an HTML or
other non-JSON body, a bare list or populated record list, an error body, an empty body, a
failed input validation and an exception. None of those says a Sophos licence is purchased:
a `status` of "ok" says a request worked, and a list of records from another vendor's API
says nothing about Sophos. This file is also wired to non-Sophos integrations, so it must
never turn such a body into a pass.

The input does not say which Sophos integration row asked, so a true flag cannot prove the
asking product's licence (an Endpoint Protection flag must not pass Firewall): that needs a
per-product licence read (getLicenses).
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
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=[VALIDATION_REASON],
                api_errors=[VALIDATION_REASON]
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
        # An unreadable body (HTML, plain text, broken JSON) proves nothing either way.
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[EXCEPTION_REASON],
            api_errors=[EXCEPTION_REASON]
        )


VALIDATION_REASON = "Not evaluated: the response failed input validation; nothing was measured."
EXCEPTION_REASON = "Not evaluated: the response could not be read (not JSON, or an unexpected shape); nothing was measured."
ERROR_REASON = "Not evaluated: the licence read returned an error instead of licence data."
NO_EVIDENCE_REASON = ("Not evaluated: the response carries no Sophos licence evidence "
                      "(no licensePurchased value and no Sophos product flag); a generic status, "
                      "HTTP code or record list does not show a licence was purchased.")
BAD_LEGACY_REASON = "Not evaluated: licensePurchased is present but is not true or false."
ERROR_KEYS = ("error", "errors", "errorCode", "errorMessage", "errorType", "fault", "PSError")
STATUS_KEYS = ("status", "statusCode", "status_code", "httpStatus")

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


def is_error_body(data):
    """True for a body that reports an error or an HTTP 4xx/5xx status."""
    for key in ERROR_KEYS:
        if data.get(key):
            return True
    for key in STATUS_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip().isdigit():
            value = int(value.strip())
        if isinstance(value, int) and not isinstance(value, bool) and value >= 400:
            return True
    return False


def sophos_license(data):
    """(True | False | None, reason, {flag: value}) for a Sophos licence or healthCheck body.

    True only from licensePurchased true. A generic status, HTTP code, list, HTML or any
    other shape is None: it is not Sophos licence evidence.
    """
    if not isinstance(data, dict) or not data:
        return None, NO_EVIDENCE_REASON, {}
    if is_error_body(data):
        return None, ERROR_REASON, {}
    if "licensePurchased" in data:
        legacy = flag_value(data.get("licensePurchased"))
        if legacy is True:
            return True, "Sophos licence confirmed (licensePurchased: true)", {}
        if legacy is False:
            return False, "Sophos licence not purchased (licensePurchased: false)", {}
        return None, BAD_LEGACY_REASON, {}

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

    return None, NO_EVIDENCE_REASON, products
