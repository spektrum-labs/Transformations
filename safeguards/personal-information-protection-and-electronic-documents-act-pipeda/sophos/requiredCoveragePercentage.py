"""
Transformation: requiredCoveragePercentage
Vendor: Sophos  |  Category: personal-information-protection-and-electronic-documents-act-pipeda
Evaluates: Coverage percentage of endpoints with Endpoint Protection product assigned vs total endpoints.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Sophos", "category": "personal-information-protection-and-electronic-documents-act-pipeda"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"requiredCoveragePercentage": False, "scoreInPercentage": 0.0, "totalEndpoints": 0, "protectedEndpoints": 0, "error": "No endpoint items found in response"}

        total = len(items)
        epp_codes = ["endpointProtection", "interceptX", "interceptXForServer", "coreAgent"]
        protected_count = 0

        for item in items:
            assigned_products = item.get("assignedProducts", [])
            codes = [p.get("code", "") for p in assigned_products]
            found = False
            for code in epp_codes:
                if code in codes:
                    found = True
                    break
            if found:
                protected_count = protected_count + 1

        coverage = (protected_count * 100) / total if total > 0 else 0.0
        threshold = 80.0
        is_sufficient = coverage >= threshold

        return {
            "requiredCoveragePercentage": is_sufficient,
            "scoreInPercentage": round(coverage, 2),
            "totalEndpoints": total,
            "protectedEndpoints": protected_count,
            "thresholdPercentage": threshold
        }
    except Exception as e:
        return {"requiredCoveragePercentage": False, "scoreInPercentage": 0.0, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
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
        coverage = extra_fields.get("scoreInPercentage", 0.0)
        total = extra_fields.get("totalEndpoints", 0)
        protected = extra_fields.get("protectedEndpoints", 0)
        threshold = extra_fields.get("thresholdPercentage", 80.0)
        if result_value:
            pass_reasons.append("EPP coverage meets the required threshold of " + str(threshold) + "%")
            pass_reasons.append("Coverage: " + str(coverage) + "% (" + str(protected) + " of " + str(total) + " endpoints protected)")
        else:
            fail_reasons.append("EPP coverage is below the required threshold of " + str(threshold) + "%")
            fail_reasons.append("Current coverage: " + str(coverage) + "% (" + str(protected) + " of " + str(total) + " endpoints protected)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Deploy Sophos Endpoint Protection to all unprotected endpoints to reach " + str(threshold) + "% coverage")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
