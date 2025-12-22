# isbackupenabled.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Evaluates whether backups are enabled on Datto BCDR devices.
    Returns: {"isBackupEnabled": bool}
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

        # Check for devices with backups
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        )

        if len(devices) > 0:
            # Check if any device has backup enabled
            for device in devices:
                if isinstance(device, list):
                    device = device[0] if len(device) > 0 else {}
                
                backup_enabled = (
                    device.get("backupEnabled", False) or
                    device.get("isProtected", False) or
                    device.get("lastBackup") is not None or
                    device.get("status", "").lower() in ["protected", "active", "ok"]
                )
                if backup_enabled:
                    return {"isBackupEnabled": True}

        return {"isBackupEnabled": False}

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}

