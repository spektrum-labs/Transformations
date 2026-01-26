# isbackupenabled.py - CrashPlan

import json
import ast

def transform(input):
    """
    Evaluates whether backups are enabled on CrashPlan.
    Counts active computers with backup enabled.
    Returns True if at least one device has active backup configured.

    Parameters:
        input (dict): The JSON data from CrashPlan listComputers endpoint.

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

        # Check for computers
        computers = (
            data.get("computers", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        total_computers = 0
        active_with_backup = 0

        if isinstance(computers, list):
            total_computers = len(computers)
            for computer in computers:
                # Check if computer is active and has backup enabled
                is_active = computer.get("active", False)
                status = computer.get("status", "").lower()
                backup_usage = computer.get("backupUsage", [])

                # Computer is considered backup-enabled if:
                # - It's active AND
                # - Status indicates connectivity (not "Deactivated", "Deauthorized") AND
                # - Has backup usage data or is in a connected state
                if is_active and status not in ["deactivated", "deauthorized", "blocked"]:
                    if backup_usage or status in ["connected", "connectedbackingup", "idle"]:
                        active_with_backup += 1
                    elif computer.get("lastConnected"):
                        # If it has connected before, consider it backup-enabled
                        active_with_backup += 1

        elif data.get("totalCount"):
            total_computers = data.get("totalCount", 0)
            active_with_backup = total_computers  # Assume all returned are active if count only

        is_backup_enabled = active_with_backup > 0

        return {
            "isBackupEnabled": is_backup_enabled,
            "totalDevices": total_computers,
            "devicesWithBackup": active_with_backup
        }

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}
