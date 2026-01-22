# isbackuptested.py - Rubrik

import json
import ast

def transform(input):
    """
    Analyzes job monitoring data for backup verification and restore test activities.
    Checks for verification job types in Rubrik.

    Parameters:
        input (dict): The JSON data from Rubrik getJobMonitoring endpoint.

    Returns:
        dict: A dictionary indicating if backups have been tested.
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        # Parse input
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        is_backup_tested = False
        test_count = 0
        last_test_date = None
        verification_jobs = []

        # Check for explicit test/verification status
        if data.get("isBackupTested") or data.get("verificationEnabled"):
            is_backup_tested = True

        # Check for jobs from job monitoring
        jobs = (
            data.get("jobs", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        # Job types that indicate backup testing/verification
        verification_job_types = [
            "recovery", "restore", "verification", "verify",
            "liveMount", "instantRecovery", "export", "download",
            "recoveryTest", "backupVerification"
        ]

        if isinstance(jobs, list):
            for job in jobs:
                if isinstance(job, list):
                    job = job[0] if len(job) > 0 else {}

                # Check job type for verification/recovery
                job_type = (job.get("jobType", "") or job.get("type", "")).lower()
                job_name = (job.get("name", "") or job.get("jobName", "")).lower()

                is_verification_job = any(
                    vtype.lower() in job_type or vtype.lower() in job_name
                    for vtype in verification_job_types
                )

                if is_verification_job:
                    is_backup_tested = True
                    test_count += 1
                    verification_jobs.append(job_type or job_name)

                    # Get job completion time
                    job_date = (
                        job.get("endTime") or
                        job.get("completedAt") or
                        job.get("startTime") or
                        job.get("date")
                    )
                    if job_date:
                        if not last_test_date or job_date > last_test_date:
                            last_test_date = job_date

                # Check for successful restore status
                job_status = job.get("status", job.get("jobStatus", "")).lower()
                if job_status in ["succeeded", "success", "completed"] and is_verification_job:
                    is_backup_tested = True

        return {
            "isBackupTested": is_backup_tested,
            "testCount": test_count,
            "lastTestDate": last_test_date,
            "verificationJobTypes": verification_jobs[:5]  # Return first 5 job types
        }

    except json.JSONDecodeError:
        return {"isBackupTested": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}
