"""
Transformation: isCompletionRateAcceptable
Vendor: NINJIO  |  Category: Security Awareness Training
Evaluates: Whether the aggregate training completion rate across all active training
"""
import json
from datetime import datetime
COMPLETION_THRESHOLD = 80

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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isCompletionRateAcceptable", "vendor": "NINJIO", "category": "Security Awareness Training"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:

        # Case 1: Response is a single statistics object (from statistics/:template_id/ endpoint)
        # Check for direct completion_rate or statistics fields
        if "completion_rate" in data or "completionRate" in data:
            rate = float(data.get("completion_rate", data.get("completionRate", 0)))
            result = rate >= COMPLETION_THRESHOLD
            return {
                "isCompletionRateAcceptable": result,
                "completionRate": round(rate, 2),
                "totalEnrolled": data.get("total_enrolled", data.get("enrolled", data.get("totalEnrolled", 0))),
                "totalCompleted": data.get("total_completed", data.get("completed", data.get("totalCompleted", 0)))
            }

        # Case 2: Response contains aggregate statistics in a 'statistics' or 'stats' block
        stats = data.get("statistics", data.get("stats", data.get("aggregate", {})))
        if stats and isinstance(stats, dict):
            total_enrolled = int(stats.get("total_enrolled", stats.get("enrolled", stats.get("totalEnrolled", 0))))
            total_completed = int(stats.get("total_completed", stats.get("completed", stats.get("totalCompleted", 0))))
            if total_enrolled > 0:
                rate = (total_completed / total_enrolled) * 100
                result = rate >= COMPLETION_THRESHOLD
                return {
                    "isCompletionRateAcceptable": result,
                    "completionRate": round(rate, 2),
                    "totalEnrolled": total_enrolled,
                    "totalCompleted": total_completed
                }

        # Case 3: Response is a list of templates, each with enrollment/completion fields
        templates = (
            data.get("results") or
            data.get("data") or
            data.get("templates") or
            data.get("items") or
            (data if isinstance(data, list) else [])
        )

        if isinstance(templates, list) and len(templates) > 0:
            total_enrolled = 0
            total_completed = 0

            for tmpl in templates:
                if not isinstance(tmpl, dict):
                    continue

                # Try various field name patterns for enrollment/completion
                enrolled = int(tmpl.get(
                    "total_enrolled", tmpl.get("enrolled", tmpl.get(
                        "totalEnrolled", tmpl.get("enrollment_count", 0)
                    ))
                ))
                completed = int(tmpl.get(
                    "total_completed", tmpl.get("completed", tmpl.get(
                        "totalCompleted", tmpl.get("completion_count", 0)
                    ))
                ))

                # If template has a direct completion_rate, use that proportionally
                if enrolled == 0 and completed == 0:
                    direct_rate = tmpl.get("completion_rate", tmpl.get("completionRate"))
                    if direct_rate is not None:
                        # Single template with direct rate: use as proxy for pass/fail
                        rate = float(direct_rate)
                        return {
                            "isCompletionRateAcceptable": rate >= COMPLETION_THRESHOLD,
                            "completionRate": round(rate, 2),
                            "totalEnrolled": 0,
                            "totalCompleted": 0
                        }

                total_enrolled += enrolled
                total_completed += completed

            if total_enrolled > 0:
                rate = (total_completed / total_enrolled) * 100
                result = rate >= COMPLETION_THRESHOLD
                return {
                    "isCompletionRateAcceptable": result,
                    "completionRate": round(rate, 2),
                    "totalEnrolled": total_enrolled,
                    "totalCompleted": total_completed
                }

        # Insufficient data to evaluate
        return {
            "isCompletionRateAcceptable": False,
            "completionRate": 0.0,
            "totalEnrolled": 0,
            "totalCompleted": 0,
            "error": "Insufficient data to calculate completion rate"
        }
    except Exception as e:
        return {"isCompletionRateAcceptable": False, "error": str(e)}


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
            recommendations.append(f"Review NINJIO configuration for {criteriaKey}")

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
