# isbackupenabled.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates whether backups are enabled on Veeam Service Provider Console.
    Checks for backup jobs and their enabled status.

    Parameters:
        input (dict): The JSON data from Veeam jobs endpoint.

    Returns:
        dict: A dictionary indicating if backups are enabled.
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

        # Drill down past response/result wrappers if present
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Check for backup jobs
        jobs = (
            data.get("items", []) or
            data.get("jobs", []) or
            data.get("data", []) or
            data.get("backupJobs", [])
        )

        total_jobs = 0
        enabled_jobs = 0

        if isinstance(jobs, list) and len(jobs) > 0:
            total_jobs = len(jobs)

            for job in jobs:
                if isinstance(job, list):
                    job = job[0] if len(job) > 0 else {}

                # Check job status/state
                is_enabled = (
                    job.get("isEnabled", True) or
                    job.get("enabled", True) or
                    job.get("status", "").lower() in ["running", "scheduled", "active", "success"] or
                    job.get("state", "").lower() in ["running", "scheduled", "active", "enabled"]
                )

                # Check if job is not disabled
                is_disabled = (
                    job.get("isDisabled", False) or
                    job.get("disabled", False) or
                    job.get("status", "").lower() in ["disabled", "stopped"] or
                    job.get("state", "").lower() in ["disabled", "stopped"]
                )

                if is_enabled and not is_disabled:
                    enabled_jobs += 1

        is_backup_enabled = total_jobs > 0 and enabled_jobs > 0

        return {
            "isBackupEnabled": is_backup_enabled,
            "totalJobs": total_jobs,
            "enabledJobs": enabled_jobs
        }

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}
