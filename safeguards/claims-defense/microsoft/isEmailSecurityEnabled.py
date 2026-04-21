"""
Transformation: isEmailSecurityEnabled
Vendor: Microsoft  |  Category: claims-defense
Evaluates: Checks subscribed SKUs for Defender for Office 365 or Exchange Online Protection license to confirm email security is enabled.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEmailSecurityEnabled", "vendor": "Microsoft", "category": "claims-defense"}
        }
    }


def is_defender_or_eop_sku(part_number):
    defender_eop_skus = [
        "ATP_ENTERPRISE",
        "DEFENDER_FOR_OFFICE_365_PLAN_1",
        "DEFENDER_FOR_OFFICE_365_PLAN_2",
        "EOP_ENTERPRISE",
        "EXCHANGESTANDARD",
        "EXCHANGEENTERPRISE",
        "EXCHANGE_S_STANDARD",
        "EXCHANGE_S_ENTERPRISE",
        "EXCHANGEESSENTIALS",
        "EXCHANGE_S_ESSENTIALS",
        "SPE_E3",
        "SPE_E5",
        "ENTERPRISEPREMIUM",
        "ENTERPRISEPACK",
        "BUSINESSPREMIUM",
        "O365_BUSINESS_PREMIUM",
        "M365_F1",
        "M365_E3",
        "M365_E5"
    ]
    upper_pn = part_number.upper()
    for sku in defender_eop_skus:
        if sku in upper_pn or upper_pn in sku:
            return True
    return False


def evaluate(data):
    try:
        skus = data.get("value", [])
        if not isinstance(skus, list):
            skus = []
        enabled_security_skus = []
        for sku in skus:
            if not isinstance(sku, dict):
                continue
            status = sku.get("capabilityStatus", "")
            part_number = sku.get("skuPartNumber", sku.get("partNumber", ""))
            if status == "Enabled" and is_defender_or_eop_sku(part_number):
                enabled_security_skus.append(part_number)
        email_security_enabled = len(enabled_security_skus) > 0
        return {
            "isEmailSecurityEnabled": email_security_enabled,
            "enabledEmailSecuritySkus": enabled_security_skus,
            "enabledSkuCount": len(enabled_security_skus)
        }
    except Exception as e:
        return {"isEmailSecurityEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEmailSecurityEnabled"
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
            pass_reasons.append("Email security is enabled via an active Defender for Office 365 or Exchange Online Protection license.")
            pass_reasons.append("Active security SKUs: " + str(extra_fields.get("enabledEmailSecuritySkus", [])))
        else:
            fail_reasons.append("No active Defender for Office 365 or Exchange Online Protection license found.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable Microsoft Defender for Office 365 or Exchange Online Protection to secure email.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"enabledSkuCount": extra_fields.get("enabledSkuCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
