# isbackupimmutable.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates if backups are immutable in Veeam VSPC.
    Checks for immutability settings, hardened repositories, and retention locks.

    Parameters:
        input (dict): The JSON data from Veeam job status endpoint.

    Returns:
        dict: A dictionary indicating if backups are immutable.
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

        is_immutable = False
        immutable_jobs = 0
        total_jobs = 0

        # Check for global immutability settings
        global_immutable = (
            data.get("immutableBackup", False) or
            data.get("immutabilityEnabled", False) or
            data.get("retentionLock", False) or
            data.get("hardenedRepository", False) or
            data.get("wormEnabled", False)
        )

        if global_immutable:
            is_immutable = True

        # Check backup jobs for immutability
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

                # Check immutability settings
                job_immutable = (
                    job.get("immutableBackup", False) or
                    job.get("immutabilityEnabled", False) or
                    job.get("retentionLock", False)
                )

                if job_immutable:
                    immutable_jobs += 1
                    is_immutable = True

                # Check storage/repository for hardened settings
                storage = job.get("storage", job.get("repository", {}))
                if isinstance(storage, dict):
                    if storage.get("isHardened", False) or storage.get("immutabilityEnabled", False):
                        is_immutable = True
                        immutable_jobs += 1
                    if storage.get("type", "").lower() in ["hardened", "immutable", "worm"]:
                        is_immutable = True
                        immutable_jobs += 1

        # Check repositories for immutability
        repositories = data.get("repositories", data.get("backupRepositories", []))
        if isinstance(repositories, list):
            for repo in repositories:
                if isinstance(repo, dict):
                    repo_immutable = (
                        repo.get("isHardened", False) or
                        repo.get("immutabilityEnabled", False) or
                        repo.get("makeRecentBackupsImmutableForDays", 0) > 0 or
                        repo.get("immutablePeriod", 0) > 0
                    )
                    if repo_immutable:
                        is_immutable = True
                        break

        # Check for insider protection (Veeam specific)
        if data.get("insiderProtection", False):
            is_immutable = True

        return {
            "isBackupImmutable": is_immutable,
            "immutableJobs": immutable_jobs,
            "totalJobs": total_jobs
        }

    except json.JSONDecodeError:
        return {"isBackupImmutable": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupImmutable": False, "error": str(e)}
