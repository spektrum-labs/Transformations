"""
Transformation: requiredCoveragePercentage
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: The percentage of endpoints that have Sophos Endpoint Protection assigned,
computed by checking assignedProducts[].code for 'endpointProtection' on each endpoint item.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def has_epp_assigned(endpoint_item):
    assigned = endpoint_item.get("assignedProducts", [])
    for product in assigned:
        code = product.get("code", "")
        if "endpointProtection" in code or "endpoint" in code.lower():
            return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {
                "requiredCoveragePercentage": 0,
                "error": "No endpoint items found in response",
                "totalEndpoints": 0,
                "coveredEndpoints": 0
            }

        total = len(items)
        covered = 0
        for ep in items:
            if has_epp_assigned(ep):
                covered = covered + 1

        percentage = (covered * 100) / total if total > 0 else 0
        percentage_rounded = int(percentage * 100) / 100

        return {
            "requiredCoveragePercentage": percentage_rounded,
            "totalEndpoints": total,
            "coveredEndpoints": covered
        }
    except Exception as e:
        return {"requiredCoveragePercentage": 0, "error": str(e)}


def transform(input):
    criteria_key = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteria_key: 0}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, 0)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteria_key and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value >= 100:
            pass_reasons.append("100% of endpoints have endpoint protection assigned")
        elif result_value > 0:
            pass_reasons.append(str(result_value) + "% of endpoints have endpoint protection assigned")
            fail_reasons.append(str(extra_fields.get("totalEndpoints", 0) - extra_fields.get("coveredEndpoints", 0)) + " endpoints are missing endpoint protection assignment")
            recommendations.append("Assign Sophos Endpoint Protection to all unprotected endpoints")
        else:
            fail_reasons.append("No endpoints have endpoint protection assigned")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Deploy Sophos Endpoint Protection to all managed endpoints")
        combined = {criteria_key: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteria_key: result_value, "totalEndpoints": extra_fields.get("totalEndpoints", 0)})
    except Exception as e:
        return create_response(
            result={criteria_key: 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
