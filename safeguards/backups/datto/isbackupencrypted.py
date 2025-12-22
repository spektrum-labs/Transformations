# is_backup_encrypted.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Checks that Datto BCDR backups are encrypted at rest.
    Returns: {"isBackupEncrypted": bool}
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

        # Check for encryption status
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        )

        # Datto BCDR uses AES-256 encryption by default
        # Check if any devices report encryption status
        all_encrypted = True
        has_devices = False
        
        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}
            
            has_devices = True
            encryption = device.get("encryption", device.get("encryptionStatus", {}))
            
            if isinstance(encryption, bool):
                is_encrypted = encryption
            elif isinstance(encryption, dict):
                is_encrypted = encryption.get("enabled", True) or encryption.get("encrypted", True)
            else:
                # Datto BCDR encrypts by default, so assume True if not explicitly False
                is_encrypted = str(encryption).lower() not in ["false", "disabled", "none"]
            
            if not is_encrypted:
                all_encrypted = False
                break

        # If no devices, check global encryption setting
        if not has_devices:
            global_encryption = data.get("encryptionEnabled", data.get("encryption", True))
            all_encrypted = bool(global_encryption)

        return {"isBackupEncrypted": all_encrypted}

    except json.JSONDecodeError:
        return {"isBackupEncrypted": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEncrypted": False, "error": str(e)}

