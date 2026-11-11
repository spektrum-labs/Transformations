"""
Transformation: confirmedLicensePurchased
Vendor: Security Ratings
Category: Risk Management / Licensing

Evaluates if the license has been purchased for Security Ratings.
"""

import json
from datetime import date, datetime


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
                "vendor": "Security Ratings",
                "category": "Risk Management"
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

        today = datetime.utcnow().date()
        subscription = subscription_of(data)
        license_purchased = is_subscribed(subscription, today)

        if license_purchased:
            pass_reasons.append("Security ratings license active")
        else:
            fail_reasons.append("License has not been purchased")
            recommendations.append("Purchase license for Security Ratings")

        return create_response(
            result={criteriaKey: license_purchased},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"licensePurchased": license_purchased,
                           "subscriptionType": subscription.get("subscription_type"),
                           "subscriptionEndDate": subscription.get("subscription_end_date")}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )


def subscription_of(data):
    """Bitsight's company-details body carries the subscription at the top level.

    The generic affirmative_signal looked for keys such as licensed or subscribed, which this
    body does not have, so every subscribed Bitsight company failed.
    """
    if not isinstance(data, dict):
        return {}
    for key in ("error", "errors", "detail"):
        if data.get(key):
            return {}
    return data


def is_subscribed(body, today):
    if not str(body.get("subscription_type") or "").strip():
        return False
    raw = body.get("subscription_end_date")
    if raw is None or str(raw).strip() == "":
        return True   # a null end date is an open-ended subscription
    # An end date that is not an ISO date fails closed: compared as text, "Dec 31, 2019" sorted after any year.
    ends = parse_day(raw)
    return ends is not None and ends >= today


def parse_day(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return date.fromisoformat(str(value)[:10])
    except Exception:
        return None
