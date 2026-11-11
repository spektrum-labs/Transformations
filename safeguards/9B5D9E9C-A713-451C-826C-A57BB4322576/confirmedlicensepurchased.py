"""
Transformation: confirmedLicensePurchased
Vendor: Firewall
Category: Network Security / Licensing

Evaluates if the license has been purchased for the Firewall.
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
                "vendor": "Firewall",
                "category": "Network Security"
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

        licenses = cato_licenses(data)
        today = datetime.utcnow().date()
        active = [l for l in licenses if is_active(l, today)]
        license_purchased = len(active) > 0

        if license_purchased:
            pass_reasons.append("Firewall license active")
        else:
            fail_reasons.append("License has not been purchased")
            recommendations.append("Purchase license for Firewall")

        return create_response(
            result={criteriaKey: license_purchased},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"licensePurchased": license_purchased,
                           "licenses": len(licenses), "activeLicenses": len(active)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )


def cato_licenses(data):
    """Cato's GraphQL `licensing` query nests licences at data.licensing.licensingInfo.licenses.

    The generic affirmative_signal saw no recognised key at that depth, so every licensed
    Cato account failed.
    """
    node = data
    for key in ("data", "licensing", "licensingInfo"):
        if isinstance(node, dict) and key in node:
            node = node[key]
    if not isinstance(node, dict):
        return []
    licenses = node.get("licenses")
    return [l for l in licenses if isinstance(l, dict)] if isinstance(licenses, list) else []


def parse_day(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return date.fromisoformat(str(value)[:10])
    except Exception:
        return None


def is_active(lic, today):
    if str(lic.get("status", "")).strip().upper() != "ACTIVE":
        return False
    raw = lic.get("expirationDate")
    if raw is None or str(raw).strip() == "":
        return True   # no expiry on the licence: not expired
    # An expiry that is not an ISO date fails closed: compared as text, "Jun 30, 2029" sorted after any year.
    expires = parse_day(raw)
    return expires is not None and expires >= today
