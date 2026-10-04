"""
Transformation: confirmedLicensePurchased
Vendor: KnowBe4 (Security Awareness Training)
Category: Compliance / Licensing

Evaluates whether a KnowBe4 subscription is purchased and current, from the account body
(GET /v1/account): `type`, `subscription_level`, `number_of_seats`, `subscription_end_date`.

  * a paid subscription whose end date is today or later        -> True
  * a subscription whose end date has passed, or a trial / free /
    expired / cancelled account type                            -> False
  * an empty, error or unrecognised body                        -> None (Not evaluated)

A legacy `licensePurchased` boolean is still honoured first.
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
                "vendor": "Compliance Management",
                "category": "Compliance"
            }
        }
    }


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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        license_purchased, reason = knowbe4_license(data)
        summary = {"licensePurchased": license_purchased}
        if isinstance(data, dict):
            summary["type"] = data.get("type")
            summary["subscriptionLevel"] = data.get("subscription_level")
            summary["numberOfSeats"] = data.get("number_of_seats")
            summary["subscriptionEndDate"] = data.get("subscription_end_date")

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
            recommendations.append("Renew or purchase a paid KnowBe4 subscription")

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


NOT_PURCHASED_TYPES = ("trial", "free", "expired", "cancelled", "canceled", "inactive", "suspended")


def parse_end_date(value):
    """'YYYY-MM-DD' (optionally followed by a time) -> datetime, else None. No strptime: the sandbox refuses it."""
    if not isinstance(value, str):
        return None
    text = value.strip()[:10]
    parts = text.split("-")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    try:
        return datetime(int(parts[0]), int(parts[1]), int(parts[2]))
    except (ValueError, TypeError):
        return None


def knowbe4_license(data):
    """(True | False | None, reason) for a KnowBe4 account body."""
    if not isinstance(data, dict) or not data:
        if affirmative_signal(data):
            return True, "License has been purchased for KnowBe4 (the read returned a populated record list)"
        return None, "Not evaluated: the KnowBe4 account read returned no data"
    if "licensePurchased" in data:
        legacy = data.get("licensePurchased")
        if isinstance(legacy, str):
            legacy = legacy.strip().lower() == "true"
        if legacy:
            return True, "License has been purchased (licensePurchased: true)"
        return False, "License has not been purchased (licensePurchased: false)"
    for key in ("error", "errors", "errorMessage", "message", "fault"):
        if data.get(key) and "type" not in data:
            return None, "Not evaluated: the KnowBe4 account read returned an error"

    account_type = data.get("type")
    account_type = account_type.strip().lower() if isinstance(account_type, str) else ""
    level = data.get("subscription_level")
    level_text = (" (" + level.strip() + ")") if isinstance(level, str) and level.strip() else ""
    raw_end = data.get("subscription_end_date")
    end = parse_end_date(raw_end)
    today = datetime.utcnow()
    today = datetime(today.year, today.month, today.day)

    if account_type in NOT_PURCHASED_TYPES:
        return False, "KnowBe4 account type is '" + account_type + "', not a paid subscription"
    if account_type == "paid":
        if end is None:
            return None, "Not evaluated: the KnowBe4 account is paid but returned no readable subscription end date"
        if end < today:
            return False, "KnowBe4 subscription" + level_text + " ended on " + raw_end.strip()[:10]
        return True, "KnowBe4 paid subscription" + level_text + " is current until " + raw_end.strip()[:10]
    if end is not None and end < today:
        return False, "KnowBe4 subscription" + level_text + " ended on " + raw_end.strip()[:10]

    # No KnowBe4 subscription fields this transform recognises. Keep the earlier positive
    # reading so nothing that passed before stops passing; anything else is not evidence
    # of a missing licence.
    if affirmative_signal(data):
        return True, "License has been purchased for KnowBe4"
    return None, "Not evaluated: the KnowBe4 account read did not include a recognised subscription field"
