"""
Transformation: isTrainingEnabled
Vendor: Proofpoint SAT  |  Category: Security Awareness Training
Evaluates: Training assignments exist in the PSAT system (total_records > 0).
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isTrainingEnabled", "vendor": "Proofpoint SAT", "category": "Security Awareness Training"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # `bool(data)` asked whether a response arrived, not what it said, so any
        # non-empty body -- including an auth-error envelope or a body reporting zero
        # assignments -- satisfied this criterion and no input could make it false.
        # Resolved from `total_records` (the field this criterion is documented against)
        # now; see has_training_assignments below.
        result = has_training_assignments(data)
        return {"isTrainingEnabled": result}

    except Exception as e:
        return {"isTrainingEnabled": False, "error": str(e)}


def has_training_assignments(data):
    """True only when the payload POSITIVELY evidences `total_records > 0`.

    Deliberately conservative: an unreadable/empty/error body, or a body naming
    `total_records` as zero or absent, is False. A non-empty population of assignment
    records under a recognised key is also accepted as evidence. Anything unrecognised
    is False -- never True by default.
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
    for container in containers:
        if "total_records" in container:
            try:
                return int(container["total_records"]) > 0
            except (TypeError, ValueError):
                return False
    for key in ("users", "assignments", "trainings", "training_assignments"):
        value = data.get(key)
        if isinstance(value, list) and value:
            return True
    return False


def transform(input):
    criteriaKey = "isTrainingEnabled"
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
