"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft Defender / Endpoint Protection
Category: Licensing

Evaluates if the license has been purchased for endpoint protection.
Searches for SKUs containing: MDE, ATP, DEFENDER, SPE_E3 (Microsoft 365 E3)

Reference:
https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Microsoft Defender",
                "category": "Licensing"
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

        criteriaValue = False
        defender_skus = []

        # Get SKU data from value array
        sku_data = []
        if isinstance(data, dict) and 'value' in data:
            sku_data = data.get("value", [])
        elif isinstance(data, list):
            sku_data = data

        for sku in sku_data:
            if isinstance(sku, dict):
                sku_part = sku.get("skuPartNumber", "").upper()
                if any(keyword in sku_part for keyword in ["MDE", "ATP", "DEFENDER", "SPE_E3"]):
                    defender_skus.append({
                        "SkuPartNumber": sku.get("skuPartNumber"),
                        "SkuId": sku.get("skuId"),
                        "CapabilityStatus": sku.get("capabilityStatus"),
                        "ConsumedUnits": sku.get("consumedUnits"),
                        "PrepaidUnits": sku.get("prepaidUnits")
                    })
                    criteriaValue = True

        if criteriaValue:
            pass_reasons.append(f"Endpoint protection license purchased: {len(defender_skus)} matching SKU(s)")
            for sku in defender_skus:
                pass_reasons.append(f"SKU: {sku['SkuPartNumber']} (Status: {sku['CapabilityStatus']})")
        else:
            fail_reasons.append("No endpoint protection license SKUs found")
            recommendations.append("Purchase Microsoft Defender for Endpoint or equivalent license")

        return create_response(
            result={criteriaKey: criteriaValue},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalSkus": len(sku_data),
                "defenderSkus": len(defender_skus)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
