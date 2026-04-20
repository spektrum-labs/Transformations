"""
Transformation: confirmedLicensePurchased
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Verify a valid Sophos license is active. Checks that items[] is non-empty and
at least one endpoint has an assignedProducts entry with a recognized Sophos product code.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"confirmedLicensePurchased": False, "error": "No endpoints found — cannot confirm active license", "totalEndpoints": 0, "licensedProductCodes": []}
        recognized_codes = ["endpointProtection", "interceptX", "interceptXAdvanced", "coreAgent", "xdr", "mtr", "ztna"]
        product_codes_found = []
        for item in items:
            assigned = item.get("assignedProducts", [])
            for prod in assigned:
                code = prod.get("code", "")
                if code in recognized_codes and code not in product_codes_found:
                    product_codes_found.append(code)
        is_licensed = len(product_codes_found) > 0
        return {
            "confirmedLicensePurchased": is_licensed,
            "totalEndpoints": len(items),
            "licensedProductCodes": product_codes_found
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
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        if result_value:
            pass_reasons.append("Active Sophos license confirmed — recognized product codes assigned to endpoints")
            codes = extra_fields.get("licensedProductCodes", [])
            pass_reasons.append("licensedProductCodes: " + ", ".join(codes))
            pass_reasons.append("totalEndpoints: " + str(extra_fields.get("totalEndpoints", 0)))
        else:
            fail_reasons.append("Could not confirm active Sophos license — no recognized product codes found on any endpoint")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure a valid Sophos subscription (e.g. Intercept X or Endpoint Protection) is purchased and activated; endpoints should show recognized assignedProducts codes")
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEndpoints": extra_fields.get("totalEndpoints", 0), "licensedProductCodes": extra_fields.get("licensedProductCodes", [])})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
