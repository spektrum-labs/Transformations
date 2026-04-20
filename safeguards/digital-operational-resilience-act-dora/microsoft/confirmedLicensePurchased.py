"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Confirms at least one qualifying Microsoft 365 security-relevant SKU is active with consumed units > 0.
"""
import json
from datetime import datetime


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


QUALIFYING_SKUS = [
    "SPE_E3", "SPE_E5", "Microsoft_365_Business_Premium",
    "DEFENDER_ENDPOINT", "ATP_ENTERPRISE", "EMS", "EMSPREMIUM",
    "AAD_PREMIUM", "AAD_PREMIUM_P2", "M365_F1", "M365_F3",
    "ENTERPRISEPREMIUM", "ENTERPRISEPREMIUM_NOPSTNCONF"
]


def get_skus(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    try:
        skus = get_skus(data)
        if not skus:
            return {"confirmedLicensePurchased": False, "error": "No subscribed SKUs found", "totalSkus": 0}

        qualifying_found = []
        all_active = []

        for sku in skus:
            part_number = sku.get("skuPartNumber", "")
            capability_status = sku.get("capabilityStatus", "")
            consumed = sku.get("consumedUnits", 0)
            if capability_status == "Enabled" and consumed > 0:
                all_active.append(part_number)
                if part_number in QUALIFYING_SKUS:
                    qualifying_found.append(part_number)

        is_confirmed = len(qualifying_found) > 0
        return {
            "confirmedLicensePurchased": is_confirmed,
            "qualifyingLicenses": ", ".join(qualifying_found),
            "totalSkus": len(skus),
            "activeSkuCount": len(all_active)
        }
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("One or more qualifying Microsoft 365 security licenses are active")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("No qualifying security-relevant Microsoft 365 SKU found with active status and consumed units > 0")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure a qualifying Microsoft 365 or Defender license (e.g. SPE_E3, SPE_E5, Microsoft_365_Business_Premium) is purchased and assigned")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
