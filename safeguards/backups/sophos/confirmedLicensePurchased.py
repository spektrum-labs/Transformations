"""
Transformation: confirmedLicensePurchased
Vendor: Sophos  |  Category: Backups
Evaluates: Confirms a valid Sophos Central license is active by verifying
that endpoints contain non-empty assignedProducts fields.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Sophos", "category": "Backups"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"confirmedLicensePurchased": False, "totalEndpoints": 0, "licensedEndpoints": 0, "scoreInPercentage": 0}

        total = len(items)
        licensed = 0
        licensed_products = []

        for endpoint in items:
            assigned = endpoint.get("assignedProducts", [])
            if assigned and len(assigned) > 0:
                licensed = licensed + 1
                for product in assigned:
                    code = product.get("code", "")
                    if code and code not in licensed_products:
                        licensed_products.append(code)

        score = int((licensed / total) * 100) if total > 0 else 0
        result = licensed > 0

        return {
            "confirmedLicensePurchased": result,
            "totalEndpoints": total,
            "licensedEndpoints": licensed,
            "scoreInPercentage": score,
            "detectedProductCodes": licensed_products
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
            pass_reasons.append("At least one endpoint has active Sophos product licenses assigned")
            licensed = extra_fields.get("licensedEndpoints", 0)
            total = extra_fields.get("totalEndpoints", 0)
            pass_reasons.append("Licensed endpoints: " + str(licensed) + " of " + str(total))
            codes = extra_fields.get("detectedProductCodes", [])
            if codes:
                pass_reasons.append("Detected product codes: " + ", ".join(codes))
        else:
            fail_reasons.append("No endpoints with assigned Sophos product licenses were found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure Sophos Central licenses are purchased and assigned to endpoints")
            recommendations.append("Check that endpoints are enrolled and reporting assigned products")

        result_dict = {"confirmedLicensePurchased": result_value}
        for k, v in extra_fields.items():
            result_dict[k] = v

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEndpoints": extra_fields.get("totalEndpoints", 0), "licensedEndpoints": extra_fields.get("licensedEndpoints", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
