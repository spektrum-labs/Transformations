# isbackuptested.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates if backups have been tested/validated in Veeam VSPC.
    Checks for SureBackup jobs, restore verification, and test restore history.

    Parameters:
        input (dict): The JSON data from Veeam job status endpoint.

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

        # Check for explicit test/verification status
        if data.get("isBackupTested") or data.get("verificationEnabled"):
            is_backup_tested = True

        # Check for SureBackup or verification jobs
        jobs = (
            data.get("items", []) or
            data.get("jobs", []) or
            data.get("data", []) or
            data.get("backupJobs", [])
        )

        if isinstance(jobs, list):
            for job in jobs:
                if isinstance(job, list):
                    job = job[0] if len(job) > 0 else {}

                # Check job type for SureBackup/verification
                job_type = (job.get("type", "") or job.get("jobType", "")).lower()
                job_name = (job.get("name", "") or job.get("jobName", "")).lower()

                if any(keyword in job_type for keyword in ["surebackup", "verification", "test", "recovery"]):
                    is_backup_tested = True
                    test_count += 1

                if any(keyword in job_name for keyword in ["surebackup", "verification", "test", "recovery", "validate"]):
                    is_backup_tested = True
                    test_count += 1

                # Check for verification settings
                if job.get("verificationEnabled") or job.get("sureBackupEnabled"):
                    is_backup_tested = True

                # Check for restore test history
                restore_tests = job.get("restoreTests", job.get("verificationHistory", []))
                if isinstance(restore_tests, list) and len(restore_tests) > 0:
                    is_backup_tested = True
                    test_count += len(restore_tests)

                    # Get last test date
                    for test in restore_tests:
                        test_date = test.get("date", test.get("testDate", test.get("completedAt")))
                        if test_date:
                            if not last_test_date or test_date > last_test_date:
                                last_test_date = test_date

                # Check for last verification date
                last_verify = job.get("lastVerification", job.get("lastTestDate"))
                if last_verify:
                    is_backup_tested = True
                    if not last_test_date or last_verify > str(last_test_date or ""):
                        last_test_date = last_verify

        return {
            "isBackupTested": is_backup_tested,
            "testCount": test_count,
            "lastTestDate": last_test_date
        }

    except json.JSONDecodeError:
        return {"isBackupTested": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}
