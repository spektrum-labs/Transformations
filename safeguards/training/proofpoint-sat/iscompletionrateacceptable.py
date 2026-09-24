"""
Transformation: isCompletionRateAcceptable
Vendor: Proofpoint SAT  |  Category: Security Awareness Training
Evaluates: Training completion rate is at or above 80%.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isCompletionRateAcceptable", "vendor": "Proofpoint SAT", "category": "Security Awareness Training"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # `bool(data)` asked whether a response arrived, not what it said, so any
        # non-empty body -- including one reporting a 0% completion rate -- satisfied
        # this criterion and no input could make it false. Resolved from the completion
        # rate the payload actually reports now; see completion_rate_acceptable below.
        result = completion_rate_acceptable(data)
        return {"isCompletionRateAcceptable": result}

    except Exception as e:
        return {"isCompletionRateAcceptable": False, "error": str(e)}


def completion_rate_acceptable(data, threshold=80):
    """True only when the payload POSITIVELY evidences a completion rate >= threshold.

    Deliberately conservative: an unreadable/empty/error body, a rate below threshold,
    or a body with no rate (and no completed/total counts to derive one from) is False.
    Never True by default.
    """
    if not isinstance(data, dict) or not data:
        return False
    for key in ("error", "errors", "errorMessage", "errorType", "fault"):
        if data.get(key):
            return False
    containers = [data]
    for nest_key in ("data", "result", "results", "response"):
        nested = data.get(nest_key)
        if isinstance(nested, dict):
            containers.append(nested)
    rate_keys = ("completion_rate", "completionRate", "complete_percentage", "completionPercentage")
    for container in containers:
        for key in rate_keys:
            if key in container:
                try:
                    return float(container[key]) >= threshold
                except (TypeError, ValueError):
                    return False
    count_pairs = (
        ("total_completed", "total_records"),
        ("completed_count", "total_count"),
        ("completedUsers", "totalUsers"),
    )
    for container in containers:
        for completed_key, total_key in count_pairs:
            if completed_key in container and total_key in container:
                try:
                    total = float(container[total_key])
                    completed = float(container[completed_key])
                except (TypeError, ValueError):
                    continue
                if total <= 0:
                    return False
                return (completed / total) * 100 >= threshold
    return False


def transform(input):
    criteriaKey = "isCompletionRateAcceptable"
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

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Proofpoint SAT configuration for {criteriaKey}")

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
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
