"""
Transformation: isCriticalFindingsMonitored
Vendor: Safe Security  |  Category: Cyber Risk Quantification
Evaluates: Whether the SAFE One platform is actively tracking and surfacing
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isCriticalFindingsMonitored", "vendor": "Safe Security", "category": "Cyber Risk Quantification"}
        }
    }


def _evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        findings = data.get("values", data.get("findings", data.get("data", [])))
        total_count = data.get("totalCount", data.get("size", 0))

        if not isinstance(findings, list):
            return {"isCriticalFindingsMonitored": False, "error": "Unexpected findings response structure"}

        # If no critical findings exist at all, platform may not be integrated
        # with any vulnerability source — this is a fail condition
        if total_count == 0 and len(findings) == 0:
            return {
                "isCriticalFindingsMonitored": False,
                "reason": "No critical findings found — platform may not be connected to a vulnerability source",
                "criticalFindingCount": 0
            }

        # Check recency: is the latest finding updated within threshold?
        most_recent_dt = None
        for finding in findings:
            for ts_field in ("updatedAt", "lastUpdated", "assessedAt", "createdAt"):
                ts_val = finding.get(ts_field)
                if ts_val:
                    try:
                        dt = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
                        if most_recent_dt is None or dt > most_recent_dt:
                            most_recent_dt = dt
                    except ValueError:
                        continue
                    break

        if most_recent_dt is not None:
            threshold = datetime.now(timezone.utc) - timedelta(days=RECENCY_THRESHOLD_DAYS)
            is_recent = most_recent_dt >= threshold
        else:
            # No timestamps found in findings — accept presence as sufficient
            is_recent = True

        reported_count = total_count if total_count > 0 else len(findings)
        result = reported_count >= 1 and is_recent
    except Exception as e:
        return {"isCriticalFindingsMonitored": False, "error": str(e)}


def transform(input):
    criteriaKey = "isCriticalFindingsMonitored"
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
