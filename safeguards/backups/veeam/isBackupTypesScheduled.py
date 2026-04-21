"""
Transformation: isBackupTypesScheduled
Vendor: Veeam  |  Category: Backup
Evaluates: Whether multiple backup jobs with active (non-manual) schedules exist,
           covering different backup job types, based on GET /api/v1/jobs response.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTypesScheduled", "vendor": "Veeam", "category": "Backup"}
        }
    }


def is_scheduled(job):
    schedule = job.get("schedule", {})
    if not isinstance(schedule, dict):
        return False
    run_manually = schedule.get("runManually", True)
    if run_manually:
        return False
    schedule_keys = ["daily", "weekly", "monthly", "periodically", "continuously", "afterJob"]
    for key in schedule_keys:
        if key in schedule and schedule.get(key):
            return True
    return False


def evaluate(data):
    try:
        jobs = data.get("data", [])
        if not isinstance(jobs, list):
            jobs = []
        total_jobs = len(jobs)
        scheduled_jobs = []
        scheduled_types = {}
        for job in jobs:
            is_disabled = job.get("isDisabled", False)
            if is_disabled:
                continue
            if is_scheduled(job):
                job_name = job.get("name", "Unknown")
                job_type = job.get("type", "Unknown")
                scheduled_jobs.append(job_name)
                if job_type not in scheduled_types:
                    scheduled_types[job_type] = 0
                scheduled_types[job_type] = scheduled_types[job_type] + 1
        scheduled_count = len(scheduled_jobs)
        type_count = len(scheduled_types)
        is_scheduled_result = scheduled_count > 0 and type_count >= 1
        return {
            "isBackupTypesScheduled": is_scheduled_result,
            "totalJobs": total_jobs,
            "scheduledJobCount": scheduled_count,
            "distinctJobTypes": type_count,
            "scheduledJobNames": scheduled_jobs,
            "jobTypeBreakdown": scheduled_types
        }
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupTypesScheduled"
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
        total_jobs = eval_result.get("totalJobs", 0)
        scheduled_count = eval_result.get("scheduledJobCount", 0)
        distinct_types = eval_result.get("distinctJobTypes", 0)
        scheduled_names = eval_result.get("scheduledJobNames", [])
        job_type_breakdown = eval_result.get("jobTypeBreakdown", {})
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append(str(scheduled_count) + " scheduled backup job(s) found covering " + str(distinct_types) + " job type(s)")
            type_summary_parts = []
            for t in job_type_breakdown:
                type_summary_parts.append(t + ": " + str(job_type_breakdown[t]))
            additional_findings.append("Job type breakdown: " + ", ".join(type_summary_parts))
            additional_findings.append("Scheduled jobs: " + ", ".join(scheduled_names))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            elif total_jobs == 0:
                fail_reasons.append("No backup jobs found in Veeam Backup and Replication")
                recommendations.append("Create scheduled backup jobs covering different backup types (e.g. full, incremental)")
            else:
                fail_reasons.append("No enabled backup jobs with an active schedule were found (" + str(total_jobs) + " total jobs)")
                recommendations.append("Configure active schedules on backup jobs rather than running them manually")
        return create_response(
            result={criteriaKey: result_value, "totalJobs": total_jobs, "scheduledJobCount": scheduled_count, "distinctJobTypes": distinct_types},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalJobs": total_jobs, "scheduledJobCount": scheduled_count, "distinctJobTypes": distinct_types})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
