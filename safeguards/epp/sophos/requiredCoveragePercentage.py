"""
Transformation: requiredCoveragePercentage
Vendor: Sophos  |  Category: epp
Evaluates: Percentage of endpoints with Sophos Endpoint Protection (endpointProtection) product assigned,
           calculated from the getEndpoints items[] array.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Sophos", "category": "epp"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []
        total = len(items)
        if total == 0:
            return {"requiredCoveragePercentage": 0.0, "totalEndpoints": 0, "protectedEndpoints": 0}
        protected = 0
        for endpoint in items:
            assigned = endpoint.get("assignedProducts", [])
            if not isinstance(assigned, list):
                assigned = []
            for product in assigned:
                if isinstance(product, dict) and product.get("code", "") == "endpointProtection":
                    protected = protected + 1
                    break
        percentage = round((protected / total) * 100, 2)
        return {
            "requiredCoveragePercentage": percentage,
            "totalEndpoints": total,
            "protectedEndpoints": protected
        }
    except Exception as e:
        return {"requiredCoveragePercentage": 0.0, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: 0.0}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, 0.0)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value > 0:
            pass_reasons.append("Endpoint Protection coverage: " + str(result_value) + "%")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        else:
            fail_reasons.append("No endpoints have Sophos Endpoint Protection (endpointProtection) assigned")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Deploy Sophos Endpoint Protection to all managed endpoints via Sophos Central")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEndpoints": extra_fields.get("totalEndpoints", 0), "protectedEndpoints": extra_fields.get("protectedEndpoints", 0), criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: 0.0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
