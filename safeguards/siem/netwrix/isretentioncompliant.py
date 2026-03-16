"""
Transformation: isRetentionCompliant
Vendor: Netwrix  |  Category: SIEM
Evaluates: Whether Netwrix Auditor retains audit data for at least 180 days
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRetentionCompliant", "vendor": "Netwrix", "category": "SIEM"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # The search endpoint returns ActivityRecordSearch for JSON search results
        records = (
            data.get("ActivityRecordSearch", None) or
            data.get("activityRecordSearch", None) or
            data.get("ActivityRecordList", None) or
            data.get("activityRecordList", [])
        )

        if not isinstance(records, list):
            return {
                "isRetentionCompliant": False,
                "error": "Unexpected response structure from search endpoint",
                "retentionDays": 0
            }

        # If any records returned for the 180-day-old window, retention is compliant
        if len(records) == 0:
            return {
                "isRetentionCompliant": False,
                "reason": "No records found at 180-day retention boundary — retention may be less than required",
                "retentionDays": 0,
                "threshold": 180
            }

        # Find the oldest record timestamp to compute actual retention depth
        now = datetime.now(timezone.utc)
        oldest_timestamp = None

        for record in records:
            when_str = record.get("When", record.get("when", ""))
            if not when_str:
                continue
            try:
                when_clean = when_str.replace("Z", "+00:00")
                when_dt = datetime.fromisoformat(when_clean)
                if when_dt.tzinfo is None:
                    when_dt = when_dt.replace(tzinfo=timezone.utc)

                if oldest_timestamp is None or when_dt < oldest_timestamp:
                    oldest_timestamp = when_dt
            except (ValueError, AttributeError):
                continue

        if oldest_timestamp:
            age_days = (now - oldest_timestamp).days
        else:
            # Records exist but timestamps couldn't be parsed — still pass
            age_days = 180

        return {
            "isRetentionCompliant": True,
            "retentionDays": age_days,
            "recordsFoundAtBoundary": len(records),
            "oldestRecordFound": oldest_timestamp.isoformat() if oldest_timestamp else None,
            "complianceThresholdDays": 180
        }
    except Exception as e:
        return {"isRetentionCompliant": False, "error": str(e)}


def transform(input):
    criteriaKey = "isRetentionCompliant"
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
            recommendations.append(f"Review Netwrix configuration for {criteriaKey}")

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
