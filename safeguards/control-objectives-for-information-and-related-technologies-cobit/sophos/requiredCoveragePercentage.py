"""
Transformation: requiredCoveragePercentage
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Calculate EPP deployment coverage percentage. Ratio of endpoints where
health.overall == 'good' and assignedProducts includes endpointProtection vs total endpoints.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"requiredCoveragePercentage": 0.0, "totalEndpoints": 0, "coveredEndpoints": 0, "error": "No endpoints found"}
        total = len(items)
        covered = 0
        for item in items:
            health = item.get("health", {})
            overall = health.get("overall", "")
            assigned = item.get("assignedProducts", [])
            has_epp = False
            for prod in assigned:
                if prod.get("code") == "endpointProtection":
                    has_epp = True
                    break
            if overall == "good" and has_epp:
                covered = covered + 1
        if total > 0:
            coverage = (covered * 100.0) / total
        else:
            coverage = 0.0
        return {
            "requiredCoveragePercentage": coverage,
            "totalEndpoints": total,
            "coveredEndpoints": covered
        }
    except Exception as e:
        return {"requiredCoveragePercentage": 0.0, "totalEndpoints": 0, "coveredEndpoints": 0, "error": str(e)}


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
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        total = extra_fields.get("totalEndpoints", 0)
        covered = extra_fields.get("coveredEndpoints", 0)
        if result_value > 0:
            pass_reasons.append("EPP coverage calculated: " + str(round(result_value, 2)) + "% of endpoints are protected")
            pass_reasons.append("coveredEndpoints: " + str(covered) + " of " + str(total))
        else:
            fail_reasons.append("EPP coverage is 0% — no endpoints reported healthy with endpointProtection assigned")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Deploy Sophos endpoint protection to all managed endpoints and ensure health.overall reports 'good'")
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEndpoints": total, "coveredEndpoints": covered, "coveragePercentage": result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: 0.0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
