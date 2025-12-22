# is_backup_immutable.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Checks that Datto BCDR backups are immutable (Cloud Deletion Defense / Ransomware Shield).
    Returns: {"isBackupImmutable": bool}
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

        # Check for immutability/ransomware shield status
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        )

        is_immutable = False
        
        # Check global immutability settings first
        global_immutable = (
            data.get("cloudDeletionDefense", False) or
            data.get("ransomwareShield", False) or
            data.get("immutableBackup", False) or
            data.get("retentionLock", False)
        )
        
        if global_immutable:
            is_immutable = True
        else:
            # Check individual devices
            for device in devices:
                if isinstance(device, list):
                    device = device[0] if len(device) > 0 else {}
                
                device_immutable = (
                    device.get("immutableBackup", False) or
                    device.get("ransomwareShield", False) or
                    device.get("cloudDeletionDefense", False) or
                    device.get("retentionLock", False)
                )
                if device_immutable:
                    is_immutable = True
                    break

        return {"isBackupImmutable": is_immutable}

    except json.JSONDecodeError:
        return {"isBackupImmutable": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupImmutable": False, "error": str(e)}

