"""
Transformation: recoveryTestCompleted
Vendor: Azure Recovery Services  |  Category: Backups
Evaluates: Whether a recovery/restore test was completed within the last 365 days
"""
import json
from datetime import datetime, timezone, timedelta


def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
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

    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    # Value-keyed: the verdict is measured only when the criterion carries a value. None means
    # the body proved nothing (empty, refusal, missing field, transform raised) and must not be graded.
    value = result.get("recoveryTestCompleted") if isinstance(result, dict) else None
    measured = value is not None
    not_measured_reasons = api_errors or transformation_errors or fail_reasons or ["recoveryTestCompleted could not be measured from the response"]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else not_measured_reasons
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
                "transformationId": "recoveryTestCompleted",
                "vendor": "Azure Recovery Services",
                "category": "Backups"
            }
        }
    }


def evaluate(data):
    """Core evaluation logic."""
    try:
        if not isinstance(data, dict):
            return {"recoveryTestCompleted": None, "error": "Response is not an object; no backup jobs to evaluate"}
        jobs = data.get('value')
        if not isinstance(jobs, list):
            # No job list at all (empty body, refusal, status stub): nothing was measured.
            # A present, empty 'value' list is a measured "no jobs" and stays False below.
            return {"recoveryTestCompleted": None, "error": "No backup job list ('value') in the response"}
        restore_jobs = [
            j for j in jobs
            if j.get('properties', {}).get('operation') == 'Restore'
            and j.get('properties', {}).get('status') == 'Completed'
        ]

        if not restore_jobs:
            return {"recoveryTestCompleted": False, "lastRestoreJob": None}

        cutoff = datetime.now(timezone.utc) - timedelta(days=365)
        recent = any(
            datetime.fromisoformat(
                j.get('properties', {}).get('endTime', '2000-01-01').replace('Z', '+00:00')
            ) > cutoff
            for j in restore_jobs
        )

        return {"recoveryTestCompleted": recent, "restoreJobCount": len(restore_jobs)}
    except Exception as e:
        return {"recoveryTestCompleted": None, "error": str(e)}


def transform(input):
    """Checks if a recovery/restore test was performed recently."""
    criteriaKey = "recoveryTestCompleted"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value is None:
            fail_reasons.append(f"{criteriaKey} not evaluated: {eval_result.get('error', 'no backup job data')}")
        elif result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Azure Recovery Services configuration for {criteriaKey}")

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
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
