# isbackuptypesscheduled.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates if backup schedules are configured in Veeam VSPC.
    Validates backup types by type (full, incremental, synthetic full, etc.).

    Parameters:
        input (dict): The JSON data from Veeam job status endpoint.

    Returns:
        dict: A dictionary with backup schedule information by type.
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

        is_scheduled = False
        has_full_backup = False
        has_incremental_backup = False
        has_synthetic_full = False
        scheduled_jobs = 0
        total_jobs = 0

        # Check for backup jobs
        jobs = (
            data.get("items", []) or
            data.get("jobs", []) or
            data.get("data", []) or
            data.get("backupJobs", [])
        )

        if isinstance(jobs, list):
            total_jobs = len(jobs)

            for job in jobs:
                if isinstance(job, list):
                    job = job[0] if len(job) > 0 else {}

                # Check schedule configuration
                schedule = job.get("schedule", job.get("scheduleOptions", {}))
                if isinstance(schedule, dict):
                    if schedule.get("enabled", False) or schedule.get("isEnabled", False):
                        is_scheduled = True
                        scheduled_jobs += 1

                    if schedule.get("runAutomatically", False):
                        is_scheduled = True
                        scheduled_jobs += 1

                    # Check for schedule frequency
                    if schedule.get("daily") or schedule.get("weekly") or schedule.get("monthly"):
                        is_scheduled = True
                elif schedule:
                    is_scheduled = True
                    scheduled_jobs += 1

                # Check backup type
                backup_type = (job.get("backupType", "") or job.get("type", "")).lower()

                if "full" in backup_type and "synthetic" not in backup_type:
                    has_full_backup = True
                    is_scheduled = True

                if "incremental" in backup_type:
                    has_incremental_backup = True
                    is_scheduled = True

                if "synthetic" in backup_type:
                    has_synthetic_full = True
                    is_scheduled = True

                # Check for backup mode
                mode = job.get("mode", job.get("backupMode", "")).lower()
                if mode in ["incremental", "reverseincremental"]:
                    has_incremental_backup = True
                    is_scheduled = True
                elif mode == "full":
                    has_full_backup = True
                    is_scheduled = True

                # Check for scheduled backup flag
                if job.get("scheduledBackup", False) or job.get("isScheduled", False):
                    is_scheduled = True
                    scheduled_jobs += 1

                # Check for active backup interval
                interval = job.get("backupInterval", job.get("interval", 0))
                if interval and interval > 0:
                    is_scheduled = True

                # Check if job is not paused/archived
                if not job.get("isPaused", False) and not job.get("isArchived", False):
                    if job.get("lastRun") or job.get("nextRun"):
                        is_scheduled = True

        return {
            "isBackupTypesScheduled": is_scheduled,
            "hasFullBackup": has_full_backup,
            "hasIncrementalBackup": has_incremental_backup,
            "hasSyntheticFullBackup": has_synthetic_full,
            "scheduledJobs": scheduled_jobs,
            "totalJobs": total_jobs
        }

    except json.JSONDecodeError:
        return {"isBackupTypesScheduled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}
