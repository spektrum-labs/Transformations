# isbackupenabledforcriticalsystems.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates if backups are enabled for critical systems in Veeam VSPC.
    Calculates coverage percentage of backups for scoped/critical systems.

    Parameters:
        input (dict): The JSON data from Veeam job status endpoint.

    Returns:
        dict: A dictionary with backup coverage information for critical systems.
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

        is_enabled_for_critical = False
        total_systems = 0
        protected_systems = 0
        coverage_percentage = 0.0

        # Check for job status information
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

                # Check for protected objects/VMs
                objects = (
                    job.get("objects", []) or
                    job.get("protectedObjects", []) or
                    job.get("includedObjects", []) or
                    job.get("vms", [])
                )

                if isinstance(objects, list):
                    total_systems += len(objects)

                    for obj in objects:
                        if isinstance(obj, dict):
                            # Check if object is protected
                            is_protected = (
                                obj.get("isProtected", True) or
                                obj.get("status", "").lower() in ["protected", "success", "ok"] or
                                obj.get("lastBackupStatus", "").lower() in ["success", "ok"]
                            )
                            if is_protected:
                                protected_systems += 1
                        else:
                            # If object is just a name/id, count as protected
                            protected_systems += 1

                # Check for object count in job
                obj_count = job.get("objectCount", job.get("vmCount", 0))
                if obj_count and not objects:
                    total_systems += obj_count
                    # If job is successful, assume all objects are protected
                    if job.get("lastStatus", "").lower() in ["success", "ok"]:
                        protected_systems += obj_count

        # Calculate coverage percentage
        if total_systems > 0:
            coverage_percentage = (protected_systems / total_systems) * 100
            is_enabled_for_critical = coverage_percentage >= 80  # 80% threshold

        # Check for explicit critical systems coverage
        if data.get("criticalSystemsCovered") or data.get("allCriticalProtected"):
            is_enabled_for_critical = True

        return {
            "isBackupEnabledForCriticalSystems": is_enabled_for_critical,
            "totalSystems": total_systems,
            "protectedSystems": protected_systems,
            "coveragePercentage": round(coverage_percentage, 2)
        }

    except json.JSONDecodeError:
        return {"isBackupEnabledForCriticalSystems": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}
