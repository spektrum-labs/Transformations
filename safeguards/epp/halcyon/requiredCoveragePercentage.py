"""
Transformation: requiredCoveragePercentage
Vendor: Halcyon  |  Category: epp
Evaluates: Checks the required coverage percentage for EPP agent deployment across all managed endpoints.
           Passes when the reported coverage percentage meets or exceeds the required threshold (default 95%).
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Halcyon", "category": "epp"}
        }
    }


def safe_float(val, default):
    if val is None:
        return default
    try:
        return float(val)
    except Exception:
        return default


def evaluate(data):
    """
    Extracts the EPP coverage percentage from the API response.
    Looks for known field names in order of specificity.
    Passes when the actual coverage meets or exceeds the required threshold (95%).
    """
    try:
        REQUIRED_THRESHOLD = 95.0

        candidate_keys = [
            "requiredCoveragePercentage",
            "coveragePercentage",
            "percentage",
            "coverage",
            "value",
            "score",
        ]

        raw_value = None
        for key in candidate_keys:
            if key in data:
                raw_value = data[key]
                break

        # Some endpoints return a nested "data" dict -- unwrap one level if needed
        if raw_value is None and isinstance(data.get("data"), dict):
            nested = data["data"]
            for key in candidate_keys:
                if key in nested:
                    raw_value = nested[key]
                    break

        # Determine whether this is a straight boolean result vs a numeric percentage
        result_value = data.get("result", None)
        passed_bool = data.get("passed", data.get("pass", None))

        # If a numeric percentage is present, evaluate against threshold
        if raw_value is not None:
            score = safe_float(raw_value, -1.0)
            if score < 0:
                passes = False
                actual_percentage = 0.0
            else:
                actual_percentage = score
                passes = actual_percentage >= REQUIRED_THRESHOLD
            return {
                "requiredCoveragePercentage": passes,
                "scoreInPercentage": actual_percentage,
                "requiredThreshold": REQUIRED_THRESHOLD,
            }

        # No numeric value found -- fall back to boolean indicators
        if result_value is not None:
            passes = bool(result_value)
            return {
                "requiredCoveragePercentage": passes,
                "scoreInPercentage": 100.0 if passes else 0.0,
                "requiredThreshold": REQUIRED_THRESHOLD,
            }

        if passed_bool is not None:
            passes = bool(passed_bool)
            return {
                "requiredCoveragePercentage": passes,
                "scoreInPercentage": 100.0 if passes else 0.0,
                "requiredThreshold": REQUIRED_THRESHOLD,
            }

        # Completely unknown shape -- return False with 0
        return {
            "requiredCoveragePercentage": False,
            "scoreInPercentage": 0.0,
            "requiredThreshold": REQUIRED_THRESHOLD,
            "error": "Could not locate a coverage percentage value in the API response",
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
                fail_reasons=["Input validation failed"],
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        score = eval_result.get("scoreInPercentage", 0.0)
        threshold = eval_result.get("requiredThreshold", 95.0)
        if result_value:
            pass_reasons.append(
                "EPP agent coverage meets the required threshold: "
                + str(score) + "% >= " + str(threshold) + "%"
            )
        else:
            fail_reasons.append(
                "EPP agent coverage does not meet the required threshold: "
                + str(score) + "% < " + str(threshold) + "%"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Deploy the Halcyon EPP agent to all unprotected endpoints to reach "
                + str(threshold) + "% coverage."
            )
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "scoreInPercentage": score},
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)],
        )
