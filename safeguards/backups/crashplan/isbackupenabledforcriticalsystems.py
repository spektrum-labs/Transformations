# isbackupenabledforcriticalsystems.py - CrashPlan

import json
import ast

def transform(input):
    """
    Calculates coverage percentage of backups for computers.
    Returns percentage of active devices with backup enabled.

    Parameters:
        input (dict): The JSON data from CrashPlan listComputers endpoint.

    Returns:
        dict: A dictionary with backup coverage metrics.
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

        # Get computers data
        computers = (
            data.get("computers", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        total_devices = 0
        active_devices = 0
        devices_with_backup = 0
        devices_connected = 0

        if isinstance(computers, list):
            total_devices = len(computers)

            for computer in computers:
                is_active = computer.get("active", False)
                status = computer.get("status", "").lower()
                last_connected = computer.get("lastConnected")
                backup_usage = computer.get("backupUsage", [])

                # Count active devices
                if is_active and status not in ["deactivated", "deauthorized", "blocked"]:
                    active_devices += 1

                    # Check if device is connected
                    if status in ["connected", "connectedbackingup", "idle"]:
                        devices_connected += 1

                    # Check if device has backup data
                    if backup_usage:
                        devices_with_backup += 1
                    elif last_connected:
                        # Device has connected and is backing up
                        devices_with_backup += 1

        elif data.get("totalCount"):
            total_devices = data.get("totalCount", 0)
            active_devices = total_devices
            devices_with_backup = total_devices

        # Calculate coverage percentage
        coverage_percentage = 0.0
        if active_devices > 0:
            coverage_percentage = round((devices_with_backup / active_devices) * 100, 2)

        # Considered enabled for critical systems if coverage is above threshold (e.g., 80%)
        is_enabled = coverage_percentage >= 80.0 or (active_devices > 0 and devices_with_backup == active_devices)

        return {
            "isBackupEnabledForCriticalSystems": is_enabled,
            "coveragePercentage": coverage_percentage,
            "totalDevices": total_devices,
            "activeDevices": active_devices,
            "devicesWithBackup": devices_with_backup,
            "devicesConnected": devices_connected
        }

    except json.JSONDecodeError:
        return {"isBackupEnabledForCriticalSystems": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}
