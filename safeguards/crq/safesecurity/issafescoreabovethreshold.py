"""
Transformation: isSAFEScoreAboveThreshold
Vendor: Safe Security  |  Category: Cyber Risk Quantification
Evaluates: Whether the organization's SAFE Score (overall risk posture grade)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSAFEScoreAboveThreshold", "vendor": "Safe Security", "category": "Cyber Risk Quantification"}
        }
    }


def _evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # Attempt letter grade evaluation first
        grade = data.get("grade", data.get("safeScore", data.get("score", data.get("scoreGrade", ""))))
        if grade and isinstance(grade, str) and len(grade) == 1 and grade.isalpha():
            result = grade.lower() in ACCEPTABLE_GRADES
            return {
                "isSAFEScoreAboveThreshold": result,
                "safeGrade": grade.upper(),
                "acceptableGrades": sorted(list(ACCEPTABLE_GRADES), reverse=True)
            }

        # Fallback: numeric breach likelihood check
        breach_likelihood = data.get(
            "breachLikelihood",
            data.get("riskScore", data.get("likelihood", data.get("overallScore", None)))
        )

        if breach_likelihood is not None:
            # Handle percentage form (e.g., 25.5) vs decimal form (e.g., 0.255)
            try:
                likelihood_val = float(breach_likelihood)
                if likelihood_val > 1.0:
                    likelihood_val = likelihood_val / 100.0  # Convert percentage to decimal
                result = likelihood_val < MAX_BREACH_LIKELIHOOD
                return {
                    "isSAFEScoreAboveThreshold": result,
                    "breachLikelihood": round(likelihood_val, 4),
                    "threshold": MAX_BREACH_LIKELIHOOD
                }
            except (ValueError, TypeError):
                pass

        # No recognizable score field found
        return {
            "isSAFEScoreAboveThreshold": False,
            "error": "Could not extract SAFE Score — verify endpoint returns grade or breachLikelihood field"
        }
    except Exception as e:
        return {"isSAFEScoreAboveThreshold": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSAFEScoreAboveThreshold"
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
        eval_result = _evaluate(data)

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
            recommendations.append(f"Review Safe Security configuration for {criteriaKey}")

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
