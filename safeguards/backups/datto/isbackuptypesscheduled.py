# is_backup_types_scheduled.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Checks if Datto BCDR backup schedules are configured.
    Returns: {"isBackupTypesScheduled": bool}
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

        # Check for backup schedules
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        )

        scheduled = False
        
        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}
            
            # Check schedule configuration
            schedule = device.get("schedule", device.get("backupSchedule", {}))
            if isinstance(schedule, dict):
                if schedule.get("enabled", False) or schedule.get("frequency"):
                    scheduled = True
                    break
            elif schedule:
                scheduled = True
                break

            # Check for scheduled backup flag
            if device.get("scheduledBackup", False):
                scheduled = True
                break
            
            # Check for backup interval
            interval = device.get("backupInterval", device.get("interval", 0))
            if interval and interval > 0:
                scheduled = True
                break

            isPaused = device.get("isPaused", False)
            if not isPaused:
                isArchived = device.get("isArchived", False)
                if not isArchived:
                    backups = device.get("backups", [])
                    if backups and len(backups) > 0:
                        scheduled = True
                        break

        return {"isBackupTypesScheduled": scheduled}

    except json.JSONDecodeError:
        return {"isBackupTypesScheduled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}

