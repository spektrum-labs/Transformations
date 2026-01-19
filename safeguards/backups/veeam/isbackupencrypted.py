# isbackupencrypted.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates if backups are encrypted in Veeam VSPC.
    Checks for encryption settings on backup jobs and repositories.

    Parameters:
        input (dict): The JSON data from Veeam job status endpoint.

    Returns:
        dict: A dictionary indicating if backups are encrypted.
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

        is_encrypted = False
        encrypted_jobs = 0
        total_jobs = 0

        # Check for global encryption setting
        global_encryption = (
            data.get("encryptionEnabled", False) or
            data.get("isEncrypted", False) or
            data.get("encryption", False)
        )

        if global_encryption:
            is_encrypted = True

        # Check backup jobs for encryption
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

                # Check encryption settings
                encryption = job.get("encryption", job.get("encryptionSettings", {}))

                if isinstance(encryption, bool):
                    if encryption:
                        encrypted_jobs += 1
                        is_encrypted = True
                elif isinstance(encryption, dict):
                    if encryption.get("enabled", False) or encryption.get("isEnabled", False):
                        encrypted_jobs += 1
                        is_encrypted = True
                    if encryption.get("algorithm") or encryption.get("keyId"):
                        encrypted_jobs += 1
                        is_encrypted = True

                # Check for encryption enabled flag
                if job.get("encryptionEnabled", False) or job.get("isEncrypted", False):
                    encrypted_jobs += 1
                    is_encrypted = True

                # Check storage/repository encryption
                storage = job.get("storage", job.get("repository", {}))
                if isinstance(storage, dict):
                    if storage.get("encryptionEnabled", False) or storage.get("isEncrypted", False):
                        is_encrypted = True

        # Check repository encryption
        repositories = data.get("repositories", data.get("backupRepositories", []))
        if isinstance(repositories, list):
            for repo in repositories:
                if isinstance(repo, dict):
                    if repo.get("encryptionEnabled", False) or repo.get("isEncrypted", False):
                        is_encrypted = True
                        break

        return {
            "isBackupEncrypted": is_encrypted,
            "encryptedJobs": encrypted_jobs,
            "totalJobs": total_jobs
        }

    except json.JSONDecodeError:
        return {"isBackupEncrypted": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEncrypted": False, "error": str(e)}
