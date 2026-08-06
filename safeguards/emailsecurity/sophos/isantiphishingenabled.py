"""
Transformation: isAntiPhishingEnabled
Vendor: Sophos  |  Category: Email Security

Evaluates whether Sophos's anti-phishing product (Central Phish Threat,
product code CPHISH) is both licensed AND actively in use, using the
Sophos Central licensing endpoint (GET /licenses/v1/licenses on the
GLOBAL host api.central.sophos.com - not the regional
api-{$dataRegion}.central.sophos.com host used elsewhere in this
integration; the regional host 404s for this endpoint).

A tenant can have CPHISH purchased but zero seats enrolled - this is
evaluated as not enabled, since a licensed-but-unused product provides
no actual anti-phishing protection.
"""
import json
from datetime import datetime

CPHISH_CODES = ["CPHISH"]


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Sophos", "category": "Email Security"}
        }
    }


def evaluate(data):
    licenses = data.get("licenses", []) if isinstance(data, dict) else []
    if not isinstance(licenses, list):
        licenses = []

    cphish = [
        lic for lic in licenses
        if isinstance(lic, dict) and lic.get("product", {}).get("code") in CPHISH_CODES
    ]

    purchased = len(cphish) > 0
    seats = cphish[0].get("quantity") if cphish else 0
    in_use_count = 0
    for lic in cphish:
        usage = lic.get("usage", {}) if isinstance(lic.get("usage"), dict) else {}
        current = usage.get("current", {}) if isinstance(usage.get("current"), dict) else {}
        in_use_count += current.get("count", 0) or 0

    in_use = in_use_count > 0
    is_enabled = purchased and in_use

    return {
        "isAntiPhishingEnabled": is_enabled,
        "purchased": purchased,
        "inUse": in_use,
        "seats": seats,
        "seatsInUse": in_use_count,
    }


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"Central Phish Threat (CPHISH) licensed ({extra_fields.get('seats', 0)} seats) and actively in use ({extra_fields.get('seatsInUse', 0)} enrolled)")
        elif extra_fields.get("purchased") and not extra_fields.get("inUse"):
            fail_reasons.append(f"Central Phish Threat is licensed ({extra_fields.get('seats', 0)} seats) but 0 users enrolled/active")
            recommendations.append("Enroll users in Sophos Central Phish Threat simulation/training campaigns")
        else:
            fail_reasons.append("Central Phish Threat (CPHISH) is not licensed for this tenant")
            recommendations.append("Purchase Sophos Central Phish Threat (CPHISH) to enable anti-phishing training/simulation")

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
