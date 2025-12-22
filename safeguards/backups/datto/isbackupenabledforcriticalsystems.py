# is_backup_enabled_for_critical_systems.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Checks that Datto BCDR backups are enabled for critical systems (servers).
    Returns: {"isBackupEnabledForCriticalSystems": bool}
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

        # Check for critical system protection
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        )

        critical_protected = False

        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}
            
            # Determine if device is critical (server)
            device_type = (
                device.get("type", "") or
                device.get("deviceType", "") or
                device.get("osType", "")
            )
            if isinstance(device_type, str):
                device_type = device_type.lower()
            else:
                device_type = ""
            
            is_critical = (
                device.get("isCritical", False) or
                device.get("criticalSystem", False) or
                device_type in ["server", "windows_server", "linux_server", "virtual_server"]
            )
            
            # Check if backup is enabled for this critical system
            backup_enabled = (
                device.get("backupEnabled", False) or
                device.get("isProtected", False) or
                device.get("lastBackup") is not None or
                device.get("status", "").lower() in ["protected", "active", "ok"]
            )
            
            if is_critical and backup_enabled:
                critical_protected = True
                break

        return {"isBackupEnabledForCriticalSystems": critical_protected}

    except json.JSONDecodeError:
        return {"isBackupEnabledForCriticalSystems": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}

