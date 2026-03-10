import json
from datetime import datetime


def extract_input(input_data):
    """
    Unwraps nested API response wrappers to extract the actual data payload.
    Supports both new format (data + validation) and legacy wrapper formats.
    """
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    data = input_data
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}

    for _ in range(3):
        if not isinstance(data, dict):
            break
        unwrapped = False
        for key in ["api_response", "response", "result", "apiResponse", "Output"]:
            if key in data and isinstance(data.get(key), (dict, list)):
                data = data[key]
                unwrapped = True
                break
        if not unwrapped:
            break

    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    """
    Builds a standardized response envelope for PostureStream consumption.
    """
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    if pass_reasons is None:
        pass_reasons = []
    if fail_reasons is None:
        fail_reasons = []
    if recommendations is None:
        recommendations = []
    if transformation_errors is None:
        transformation_errors = []
    if api_errors is None:
        api_errors = []
    if additional_findings is None:
        additional_findings = []
    if input_summary is None:
        input_summary = {}

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if api_errors else "success",
                "errors": api_errors
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors,
                "inputSummary": input_summary
            },
            "evaluation": {
                "passReasons": pass_reasons,
                "failReasons": fail_reasons,
                "recommendations": recommendations,
                "additionalFindings": additional_findings
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "schemaVersion": "1.0",
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Microsoft Intune",
                "category": "Asset Management"
            }
        }
    }


def transform(input):
    """
    Validates that an active Intune license exists by checking subscribedSkus
    for Intune-related SKU part numbers.

    Known Intune SKUs: INTUNE_A (standalone), EMS (Enterprise Mobility + Security),
    SPE_E3/SPE_E5 (Microsoft 365 E3/E5), EMSPREMIUM (EMS E5),
    M365_E3/M365_E5 (Microsoft 365 plans).

    Returns true if any Intune-capable SKU is found with enabled units > 0.
    Returns false if no matching SKUs or all are disabled/expired.
    """
    criteriaKey = "confirmedLicensePurchased"

    INTUNE_SKUS = [
        "INTUNE_A", "EMS", "EMSPREMIUM", "SPE_E3", "SPE_E5",
        "M365_E3", "M365_E5", "MICROSOFT_365_E3", "MICROSOFT_365_E5",
        "ENTERPRISEPREMIUM", "ENTERPRISEPACK", "SMB_BUSINESS_PREMIUM",
        "BUSINESS_PREMIUM", "M365_BUSINESS_PREMIUM"
    ]

    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)

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

        skus = []
        if isinstance(data, list):
            skus = data
        elif isinstance(data, dict):
            skus = data.get("value", data.get("skus", []))
            if isinstance(skus, dict):
                skus = [skus]

        if not isinstance(skus, list):
            skus = []

        matching_skus = []
        for sku in skus:
            if not isinstance(sku, dict):
                continue
            sku_part = str(sku.get("skuPartNumber", "")).upper()
            if sku_part in INTUNE_SKUS:
                enabled_units = sku.get("prepaidUnits", {}).get("enabled", 0)
                if enabled_units > 0:
                    matching_skus.append({
                        "skuPartNumber": sku_part,
                        "enabledUnits": enabled_units
                    })

        license_valid = len(matching_skus) > 0

        if license_valid:
            sku_names = [s["skuPartNumber"] for s in matching_skus]
            pass_reasons.append(
                "Found Intune-capable license(s): %s" % ", ".join(sku_names)
            )
        else:
            fail_reasons.append(
                "No active Intune-capable SKU found in subscribedSkus"
            )
            recommendations.append(
                "Ensure the tenant has an active Intune license (standalone "
                "INTUNE_A, or bundled via EMS, Microsoft 365 E3/E5, or "
                "Business Premium)"
            )

        input_summary = {
            "totalSkus": len(skus),
            "matchingSkus": len(matching_skus)
        }

        return create_response(
            result={criteriaKey: license_valid},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
