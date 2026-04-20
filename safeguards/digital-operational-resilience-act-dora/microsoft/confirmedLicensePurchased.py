"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Whether at least one qualifying Microsoft 365 or Entra ID license is active with capabilityStatus Enabled.
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


def evaluate(data):
    try:
        skus = data.get("value", [])
        qualifying_skus = [
            "SPE_E3", "SPE_E5", "SPE_E5_CALLINGMINUTES",
            "AAD_PREMIUM", "AAD_PREMIUM_P2",
            "ENTERPRISEPACK", "ENTERPRISEPREMIUM",
            "SPB", "M365_F1", "M365_F3",
            "DEVELOPERPACK_E5", "Microsoft_Teams_Essentials",
            "O365_BUSINESS_PREMIUM", "MCOEV"
        ]
        found_licenses = []
        all_enabled = []
        for sku in skus:
            part_number = sku.get("skuPartNumber", "")
            status = sku.get("capabilityStatus", "")
            if status.lower() == "enabled":
                all_enabled.append(part_number)
                is_qualifying = False
                for q in qualifying_skus:
                    if q.lower() == part_number.lower():
                        is_qualifying = True
                        break
                if is_qualifying:
                    found_licenses.append(part_number)
        has_qualifying = len(found_licenses) > 0
        return {
            "confirmedLicensePurchased": has_qualifying,
            "qualifyingLicensesFound": found_licenses,
            "totalEnabledSkus": len(all_enabled),
            "totalSkus": len(skus)
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
            pass_reasons.append("At least one qualifying Microsoft 365 or Entra ID license is active")
            pass_reasons.append("Qualifying licenses: " + str(extra_fields.get("qualifyingLicensesFound", [])))
        else:
            fail_reasons.append("No qualifying license with capabilityStatus Enabled was found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Purchase and activate a qualifying Microsoft 365 E3/E5 or Entra ID P1/P2 license to meet DORA compliance requirements")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=summary_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
