"""
Transformation: requiredCoveragePercentage
Vendor: MDR (mdr)  |  Category: MDR
Evaluates: The percentage of organisational endpoints currently enrolled under MDR
           monitoring. Derives actual coverage from the getMDREndpoints 'items' array
           and 'total'/'size' pagination fields, then validates against the attested
           coveragePercentage and a minimum required threshold of 80%.
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "requiredCoveragePercentage",
                "vendor": "mdr",
                "category": "MDR"
            }
        }
    }


def safe_round(value, decimals):
    multiplier = 1
    for i in range(decimals):
        multiplier = multiplier * 10
    rounded = int(value * multiplier + 0.5) / multiplier
    return rounded


def evaluate(data):
    try:
        items = data.get("items", [])
        total_pages = data.get("total", 0)
        page_size = data.get("size", 0)
        attested_coverage = data.get("coveragePercentage", 0)

        if not isinstance(items, list):
            items = []

        enrolled_count = len(items)

        total_endpoints = 0
        if total_pages and page_size:
            total_endpoints = total_pages * page_size
        elif enrolled_count > 0:
            total_endpoints = enrolled_count

        coverage_percentage = 0.0
        if total_endpoints > 0:
            raw = (enrolled_count / total_endpoints) * 100.0
            coverage_percentage = safe_round(raw, 2)
            if coverage_percentage > 100.0:
                coverage_percentage = 100.0
        elif attested_coverage > 0:
            coverage_percentage = float(attested_coverage)

        required_threshold = 80.0
        meets_threshold = coverage_percentage >= required_threshold

        return {
            "requiredCoveragePercentage": meets_threshold,
            "coveragePercentage": coverage_percentage,
            "enrolledEndpoints": enrolled_count,
            "totalEndpoints": total_endpoints,
            "attestedCoveragePercentage": float(attested_coverage),
            "requiredThreshold": required_threshold
        }
    except Exception as e:
        return {"requiredCoveragePercentage": False, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        coverage = extra_fields.get("coveragePercentage", 0.0)
        threshold = extra_fields.get("requiredThreshold", 80.0)
        enrolled = extra_fields.get("enrolledEndpoints", 0)
        total = extra_fields.get("totalEndpoints", 0)

        if result_value:
            pass_reasons.append(
                "MDR endpoint coverage of " + str(coverage) + "% meets the required threshold of " +
                str(threshold) + "%"
            )
            pass_reasons.append(
                "Enrolled endpoints: " + str(enrolled) + " of " + str(total)
            )
        else:
            fail_reasons.append(
                "MDR endpoint coverage of " + str(coverage) + "% is below the required threshold of " +
                str(threshold) + "%"
            )
            fail_reasons.append(
                "Enrolled endpoints: " + str(enrolled) + " of " + str(total)
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Enrol additional endpoints under MDR monitoring to reach at least " +
                str(threshold) + "% coverage of the total endpoint estate"
            )

        additional_findings.append(
            "attestedCoveragePercentage: " + str(extra_fields.get("attestedCoveragePercentage", 0.0))
        )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "enrolledEndpoints": enrolled,
                "totalEndpoints": total,
                "coveragePercentage": coverage,
                "requiredThreshold": threshold
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
