"""
Transformation: isBackupTested
Vendor: Commvault  |  Category: Backups
Evaluates: Whether a restore/recovery test job has been completed within the past 90 days.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTested", "vendor": "Commvault", "category": "Backups"}
        }
    }


def _evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        result = False
        restore_jobs_found = 0
        most_recent_date = None
        threshold_days = 90

        jobs = (
            data.get("jobs") or
            data.get("jobList") or
            data.get("items") or
            []
        )

        if not isinstance(jobs, list):
            return {"isBackupTested": False, "reason": "No job list in response"}

        COMPLETED_STATUSES = {"completed", "success", "finished"}
        now = datetime.now(tz=timezone.utc)
        cutoff = now - timedelta(days=threshold_days)

        for job_wrapper in jobs:
            # Job summary is typically nested under jobSummary
            job = job_wrapper.get("jobSummary", job_wrapper)

            job_type = str(job.get("jobType", job.get("operationType", ""))).lower()

            # Accept any restore-type job
            if "restore" not in job_type and "recovery" not in job_type:
                continue

            status = str(job.get("status", job.get("jobStatus", ""))).lower()
            if not any(s in status for s in COMPLETED_STATUSES):
                continue

            # Check recency via jobStartTime (Unix timestamp)
            start_time = job.get("jobStartTime", job.get("startTime"))
            if start_time:
                try:
                    job_dt = datetime.fromtimestamp(int(start_time), tz=timezone.utc)
                    if job_dt >= cutoff:
                        restore_jobs_found += 1
                        if most_recent_date is None or job_dt > most_recent_date:
                            most_recent_date = job_dt
                except (ValueError, TypeError, OSError):
                    # If timestamp is unparseable, count the job anyway
                    restore_jobs_found += 1

        result = restore_jobs_found > 0
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupTested"
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
            recommendations.append(f"Review Commvault configuration for {criteriaKey}")

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
