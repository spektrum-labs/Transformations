# is_backup_logging_enabled.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Checks whether logging and alerts are enabled for Datto BCDR.
    Returns: {"isBackupLoggingEnabled": bool}
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

        # Check for logging/alerting configuration
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        )

        logging_enabled = False

        # Check global logging settings
        global_logging = (
            data.get("loggingEnabled", False) or
            data.get("alertsEnabled", False) or
            data.get("notifications", {}).get("enabled", False)
        )
        
        if global_logging:
            logging_enabled = True
        else:
            # Check individual devices
            for device in devices:
                if isinstance(device, list):
                    device = device[0] if len(device) > 0 else {}
                
                device_logging = (
                    device.get("loggingEnabled", False) or
                    device.get("alertsEnabled", False) or
                    device.get("notifications", {}).get("enabled", False)
                )
                
                # If device has backups, assume logging is enabled (Datto logs by default)
                if device.get("backupEnabled", False) or device.get("lastBackup"):
                    logging_enabled = True
                    break
                    
                if device_logging:
                    logging_enabled = True
                    break

        return {"isBackupLoggingEnabled": logging_enabled}

    except json.JSONDecodeError:
        return {"isBackupLoggingEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}

