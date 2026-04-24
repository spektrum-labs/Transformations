"""
Transformation: isBackupEnabled
Vendor: Veeam  |  Category: Backup
Evaluates: Whether at least one backup job exists and is in an enabled (non-disabled) state
           based on GET /api/v1/jobs response.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabled", "vendor": "Veeam", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        jobs = data.get("data", [])
        if not isinstance(jobs, list):
            jobs = []
        total_jobs = len(jobs)
        enabled_jobs = []
        for job in jobs:
            is_disabled = job.get("isDisabled", False)
            if not is_disabled:
                enabled_jobs.append(job.get("name", "Unknown"))
        enabled_count = len(enabled_jobs)
        is_enabled = enabled_count > 0
        return {
            "isBackupEnabled": is_enabled,
            "totalJobs": total_jobs,
            "enabledJobCount": enabled_count,
            "enabledJobNames": enabled_jobs
        }
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabled"
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
        enabled_count = eval_result.get("enabledJobCount", 0)
        enabled_names = eval_result.get("enabledJobNames", [])
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append(str(enabled_count) + " enabled backup job(s) found out of " + str(total_jobs) + " total jobs")
            additional_findings.append("Enabled jobs: " + ", ".join(enabled_names))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            elif total_jobs == 0:
                fail_reasons.append("No backup jobs found in Veeam Backup and Replication")
                recommendations.append("Create and enable at least one backup job in Veeam")
            else:
                fail_reasons.append("All " + str(total_jobs) + " backup job(s) are disabled")
                recommendations.append("Enable at least one backup job in the Veeam job configuration")
        return create_response(
            result={criteriaKey: result_value, "totalJobs": total_jobs, "enabledJobCount": enabled_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalJobs": total_jobs, "enabledJobCount": enabled_count})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
