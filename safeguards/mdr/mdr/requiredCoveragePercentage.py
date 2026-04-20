"""
Transformation: requiredCoveragePercentage
Vendor: MDR (Sophos)  |  Category: MDR
Evaluates: The percentage of total managed endpoints covered by Sophos MDR.
Compares the count of endpoints with managed=true against the total endpoint count.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "MDR", "category": "MDR"}
        }
    }


def is_mdr_covered(endpoint):
    assigned_products = endpoint.get("assignedProducts", [])
    if isinstance(assigned_products, list):
        for product in assigned_products:
            if isinstance(product, dict):
                code = product.get("code", "")
                if isinstance(code, str) and "mdr" in code.lower():
                    return True
    if endpoint.get("managed", False):
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []
        total_endpoints = len(items)
        if total_endpoints == 0:
            pages = data.get("pages", {})
            total_from_pages = 0
            if isinstance(pages, dict):
                total_from_pages = pages.get("total", 0)
                if not isinstance(total_from_pages, int):
                    total_from_pages = 0
            return {
                "requiredCoveragePercentage": 0.0,
                "totalEndpoints": total_from_pages,
                "coveredEndpoints": 0,
                "scoreInPercentage": 0.0
            }
        covered_count = 0
        for endpoint in items:
            if is_mdr_covered(endpoint):
                covered_count = covered_count + 1
        percentage = (covered_count * 100.0) / total_endpoints
        rounded_percentage = int(percentage * 100 + 0.5) / 100.0
        return {
            "requiredCoveragePercentage": rounded_percentage,
            "totalEndpoints": total_endpoints,
            "coveredEndpoints": covered_count,
            "scoreInPercentage": rounded_percentage
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
        additional_findings = []
        total = extra_fields.get("totalEndpoints", 0)
        covered = extra_fields.get("coveredEndpoints", 0)
        additional_findings.append("Total endpoints: " + str(total))
        additional_findings.append("MDR-covered endpoints: " + str(covered))
        additional_findings.append("Coverage percentage: " + str(result_value) + "%")
        if result_value >= 100.0:
            pass_reasons.append("All endpoints are covered by Sophos MDR (" + str(covered) + "/" + str(total) + ").")
        elif result_value > 0.0:
            fail_reasons.append("Only " + str(result_value) + "% of endpoints are covered by Sophos MDR (" + str(covered) + "/" + str(total) + ").")
            recommendations.append("Ensure all endpoints have Sophos MDR assigned to achieve 100% coverage.")
        else:
            fail_reasons.append("No endpoints are covered by Sophos MDR.")
            recommendations.append("Assign Sophos MDR to all managed endpoints in Sophos Central.")
        if "error" in eval_result:
            fail_reasons.append(eval_result["error"])
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEndpoints": total, "coveredEndpoints": covered, "scoreInPercentage": result_value},
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: 0.0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
