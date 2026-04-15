"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft Defender / Endpoint Protection
Category: Licensing

Evaluates if a Defender license has been purchased by inspecting each SKU's
servicePlans for Defender entitlements (the authoritative source). Defender
is delivered via bundles (e.g. M365 E5 / SPE_E5) and standalone add-ons,
so matching on skuPartNumber alone misses many valid entitlements.

A SKU is considered to carry Defender when:
  - capabilityStatus == "Enabled"
  - prepaidUnits.enabled > 0
  - it contains at least one servicePlan whose name is a known Defender
    plan (or matches a Defender keyword) with provisioningStatus == "Success"

Reference:
https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
"""

import json
from datetime import datetime


DEFENDER_SERVICE_PLANS = {
    # Defender for Endpoint
    "WINDEFATP",
    "MDE_LITE",
    "MDE_SMB",
    "MICROSOFT_DEFENDER_FOR_ENDPOINT_PLAN_1",
    "MICROSOFT_DEFENDER_FOR_ENDPOINT_PLAN_2",
    "MDATP_XPLAT",
    # Defender for Office 365
    "ATP_ENTERPRISE",
    "THREAT_INTELLIGENCE",
    # Defender for Identity
    "ATA",
    # Defender for Cloud Apps
    "ADALLOM_S_STANDALONE",
    "ADALLOM_FOR_AATP",
    # Defender for IoT
    "DEFENDER_FOR_IOT_ENTERPRISE",
    # Vulnerability Management (Defender TVM)
    "TVM_PREMIUM_1",
    "TVM_PREMIUM_2",
    # Common Defender platform
    "COMMON_DEFENDER_PLATFORM_FOR_OFFICE",
}

DEFENDER_KEYWORDS = ("DEFENDER", "WINDEFATP", "MDATP", "MDE_", "ATP_")


def _is_defender_plan(plan_name):
    name = (plan_name or "").upper()
    if not name:
        return False
    if name in DEFENDER_SERVICE_PLANS:
        return True
    return any(keyword in name for keyword in DEFENDER_KEYWORDS)


def _sku_is_active(sku):
    if sku.get("capabilityStatus") != "Enabled":
        return False
    prepaid = sku.get("prepaidUnits") or {}
    try:
        return int(prepaid.get("enabled", 0) or 0) > 0
    except (TypeError, ValueError):
        return False


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
            if not isinstance(sku, dict):
                continue
            if not _sku_is_active(sku):
                continue

            matched_plans = []
            for sp in sku.get("servicePlans", []) or []:
                if not isinstance(sp, dict):
                    continue
                if sp.get("provisioningStatus") != "Success":
                    continue
                if _is_defender_plan(sp.get("servicePlanName")):
                    matched_plans.append(sp.get("servicePlanName"))

            if matched_plans:
                defender_skus.append({
                    "SkuPartNumber": sku.get("skuPartNumber"),
                    "SkuId": sku.get("skuId"),
                    "CapabilityStatus": sku.get("capabilityStatus"),
                    "ConsumedUnits": sku.get("consumedUnits"),
                    "PrepaidUnits": sku.get("prepaidUnits"),
                    "DefenderServicePlans": matched_plans,
                })
                criteriaValue = True

        if criteriaValue:
            total_plans = sum(len(s["DefenderServicePlans"]) for s in defender_skus)
            pass_reasons.append(
                f"Defender license purchased: {len(defender_skus)} SKU(s) carrying "
                f"{total_plans} Defender service plan(s)"
            )
            for sku in defender_skus:
                plans = ", ".join(sku["DefenderServicePlans"])
                prepaid_enabled = (sku["PrepaidUnits"] or {}).get("enabled")
                pass_reasons.append(
                    f"SKU {sku['SkuPartNumber']} (enabled={prepaid_enabled}, "
                    f"consumed={sku['ConsumedUnits']}) -> {plans}"
                )
        else:
            fail_reasons.append(
                "No active SKU with a Defender service plan found "
                "(checked servicePlans for WINDEFATP, ATP_ENTERPRISE, MDE, TVM_PREMIUM, etc.)"
            )
            recommendations.append("Purchase Microsoft Defender for Endpoint, M365 E5, or an equivalent Defender-bearing license")

        return create_response(
            result={criteriaKey: criteriaValue},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalSkus": len(sku_data),
                "defenderSkus": len(defender_skus),
                "matchedSkuPartNumbers": [s["SkuPartNumber"] for s in defender_skus],
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
