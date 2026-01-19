# isbackuploggingenabled.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates if backup logging is enabled on Veeam Service Provider Console.
    Checks for job history, audit logs, and logging configuration.

    Parameters:
        input (dict): The JSON data from Veeam jobs endpoint.

    Returns:
        dict: A dictionary indicating if backup logging is enabled.
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

        is_logging_enabled = False

        # Check for explicit logging configuration
        logging_enabled = data.get("loggingEnabled", data.get("auditLoggingEnabled", None))
        if logging_enabled is not None:
            is_logging_enabled = bool(logging_enabled)

        # Check for backup jobs with history/logs
        jobs = (
            data.get("items", []) or
            data.get("jobs", []) or
            data.get("data", []) or
            data.get("backupJobs", [])
        )

        if isinstance(jobs, list) and len(jobs) > 0:
            for job in jobs:
                if isinstance(job, list):
                    job = job[0] if len(job) > 0 else {}

                # Check for job history/logs
                if job.get("lastRun") or job.get("lastRunTime") or job.get("lastResult"):
                    is_logging_enabled = True
                    break

                # Check for session history
                if job.get("sessions") or job.get("history") or job.get("logs"):
                    is_logging_enabled = True
                    break

                # Check for result status (indicates logging of results)
                if job.get("lastStatus") or job.get("resultStatus"):
                    is_logging_enabled = True
                    break

        # Check for audit logs
        audit_logs = data.get("auditLogs", data.get("logs", []))
        if isinstance(audit_logs, list) and len(audit_logs) > 0:
            is_logging_enabled = True

        # If we have valid data, Veeam logs by default
        if not is_logging_enabled and isinstance(jobs, list) and len(jobs) > 0:
            is_logging_enabled = True

        return {
            "isBackupLoggingEnabled": is_logging_enabled
        }

    except json.JSONDecodeError:
        return {"isBackupLoggingEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}
