"""
Transformation: isBackupTested
Vendor: AWS  |  Category: nydfs
Evaluates: Whether AWS Backup restore jobs have been executed successfully to verify backup recoverability.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTested", "vendor": "AWS", "category": "nydfs"}
        }
    }


def evaluate(data):
    try:
        restore_jobs = data.get("RestoreJobs", [])
        if not isinstance(restore_jobs, list):
            restore_jobs = []
        total_jobs = len(restore_jobs)
        completed_jobs = []
        failed_jobs = []
        aborted_jobs = []
        other_jobs = []
        for job in restore_jobs:
            job_id = job.get("RestoreJobId", "unknown")
            status = job.get("Status", "")
            status_upper = status.upper() if isinstance(status, str) else ""
            if status_upper == "COMPLETED":
                completed_jobs.append(job_id)
            elif status_upper in ("FAILED", "ABORTED"):
                failed_jobs.append(job_id)
            else:
                other_jobs.append(job_id)
        is_tested = len(completed_jobs) > 0
        return {
            "isBackupTested": is_tested,
            "totalRestoreJobs": total_jobs,
            "completedRestoreJobCount": len(completed_jobs),
            "failedOrAbortedJobCount": len(failed_jobs),
            "otherStatusJobCount": len(other_jobs),
            "mostRecentCompletedJobIds": completed_jobs[:5]
        }
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total_jobs = eval_result.get("totalRestoreJobs", 0)
        completed_count = eval_result.get("completedRestoreJobCount", 0)
        failed_count = eval_result.get("failedOrAbortedJobCount", 0)
        recent_ids = eval_result.get("mostRecentCompletedJobIds", [])
        if result_value:
            pass_reasons.append("At least one AWS Backup restore job with status COMPLETED was found, confirming backup recoverability has been tested.")
            pass_reasons.append("Completed restore jobs: " + str(completed_count) + " of " + str(total_jobs) + " total jobs.")
            if recent_ids:
                additional_findings.append("Sample completed restore job IDs: " + ", ".join([str(j) for j in recent_ids]))
        else:
            if total_jobs == 0:
                fail_reasons.append("No AWS Backup restore jobs were found. No restore test has ever been performed in this account/region.")
            else:
                fail_reasons.append("No restore jobs with COMPLETED status were found. Total jobs: " + str(total_jobs) + ", failed/aborted: " + str(failed_count) + ".")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append("Perform a restore test by initiating a restore job from an existing AWS Backup recovery point. Verify the job completes with COMPLETED status to confirm backup recoverability.")
            recommendations.append("Schedule periodic restore tests (e.g. quarterly) to satisfy NYDFS backup testing requirements.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalRestoreJobs": total_jobs, "completedRestoreJobCount": completed_count, "isBackupTested": result_value}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
