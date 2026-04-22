"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft  |  Category: emailsecurity
Evaluates: Checks if the tenant has an active email security license (Defender for Office 365, E3/E5, Business Premium, or Exchange Online).
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Microsoft", "category": "emailsecurity"}
        }
    }


def sku_qualifies(sku):
    part_number = sku.get("skuPartNumber", "").upper()
    capability_status = sku.get("capabilityStatus", "")
    if capability_status != "Enabled":
        return False
    qualifying_keywords = [
        "SPE_E5", "SPE_E3", "SPB", "DEFENDER", "EOP",
        "EXCHANGESTANDARD", "EXCHANGEENTERPRISE", "ENTERPRISEPREMIUM",
        "ENTERPRISEPACK", "O365_BUSINESS_PREMIUM", "M365_BUSINESS"
    ]
    for keyword in qualifying_keywords:
        if keyword in part_number:
            return True
    service_plans = sku.get("servicePlans", [])
    for plan in service_plans:
        plan_name = plan.get("servicePlanName", "").upper()
        plan_status = plan.get("provisioningStatus", "")
        atp_keywords = ["ATP_ENTERPRISE", "EOP_ENTERPRISE", "EXCHANGE_S_ENTERPRISE"]
        for kw in atp_keywords:
            if kw in plan_name and plan_status == "Success":
                return True
    return False


def evaluate(data):
    try:
        skus = data.get("value", [])
        if not skus:
            nested = data.get("getSubscribedSkus", {})
            if isinstance(nested, dict):
                skus = nested.get("value", [])
        if not isinstance(skus, list):
            skus = []
        qualifying_skus = [sku for sku in skus if sku_qualifies(sku)]
        qualifying_names = [sku.get("skuPartNumber", "") for sku in qualifying_skus]
        total_skus = len(skus)
        qualifying_count = len(qualifying_skus)
        is_licensed = qualifying_count > 0
        return {
            "confirmedLicensePurchased": is_licensed,
            "totalSkus": total_skus,
            "qualifyingSkuCount": qualifying_count,
            "qualifyingSkuNames": ", ".join(qualifying_names) if qualifying_names else "None"
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
            pass_reasons.append("Active qualifying email security license found")
            qnames = eval_result.get("qualifyingSkuNames", "None")
            if qnames and qnames != "None":
                pass_reasons.append("Qualifying SKUs: " + qnames)
        else:
            fail_reasons.append("No active qualifying email security license detected")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Purchase Microsoft Defender for Office 365 Plan 1 or Plan 2, Microsoft 365 E3/E5, or Business Premium to ensure email security coverage")
        merged_result = {criteriaKey: result_value}
        for k in extra_fields:
            merged_result[k] = extra_fields[k]
        return create_response(
            result=merged_result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={"totalSkus": eval_result.get("totalSkus", 0), "qualifyingSkuCount": eval_result.get("qualifyingSkuCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
