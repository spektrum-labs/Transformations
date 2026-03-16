"""
Transformation: isLogIngestActionActive
Vendor: Netwrix  |  Category: SIEM
Evaluates: Whether Netwrix Auditor is actively ingesting log data by verifying
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isLogIngestActionActive", "vendor": "Netwrix", "category": "SIEM"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # Netwrix returns ActivityRecordList array at top level (JSON format)
        records = data.get("ActivityRecordList", data.get("activityRecordList", []))

        if not isinstance(records, list):
            return {
                "isLogIngestionActive": False,
                "error": "ActivityRecordList not found or malformed",
                "recordCount": 0
            }

        if len(records) == 0:
            return {
                "isLogIngestionActive": False,
                "reason": "No activity records returned — ingestion may be stopped or unconfigured",
                "recordCount": 0
            }

        # Check that at least one record has a recent timestamp (within 48 hours)
        threshold = datetime.now(timezone.utc) - timedelta(hours=48)
        latest_timestamp = None
        recent_count = 0

        for record in records:
            when_str = record.get("When", record.get("when", ""))
            if not when_str:
                continue
            try:
                # Netwrix timestamps are ISO 8601: "2024-03-09T14:30:00.000Z" or "2024-03-09T14:30:00"
                when_clean = when_str.replace("Z", "+00:00")
                when_dt = datetime.fromisoformat(when_clean)
                if when_dt.tzinfo is None:
                    when_dt = when_dt.replace(tzinfo=timezone.utc)

                if latest_timestamp is None or when_dt > latest_timestamp:
                    latest_timestamp = when_dt

                if when_dt >= threshold:
                    recent_count += 1
            except (ValueError, AttributeError):
                continue

        result = recent_count > 0

        return {
            "isLogIngestionActive": result,
            "recordCount": len(records),
            "recentRecords": recent_count,
            "latestRecord": latest_timestamp.isoformat() if latest_timestamp else None,
            "thresholdHours": 48
        }
    except Exception as e:
        return {"isLogIngestActionActive": False, "error": str(e)}


def transform(input):
    criteriaKey = "isLogIngestActionActive"
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
