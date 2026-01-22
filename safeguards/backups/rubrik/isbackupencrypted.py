# isbackupencrypted.py - Rubrik

import json
import ast

def transform(input):
    """
    Checks cluster encryption at rest status.
    Returns True if isEncryptionEnabled is true.

    Parameters:
        input (dict): The JSON data from Rubrik getEncryptionStatus endpoint.

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
        encryption_managed = False

        # Check for Rubrik's encryption status fields
        is_encrypted = data.get("isEncryptionEnabled", False)
        encryption_managed = data.get("encryptionManaged", False)

        # Check alternative field names
        if not is_encrypted:
            is_encrypted = (
                data.get("encryptionEnabled", False) or
                data.get("isEncrypted", False) or
                data.get("encryption", False)
            )

        # Check for encryption configuration object
        encryption_config = data.get("encryptionConfig", data.get("encryption", {}))
        if isinstance(encryption_config, dict):
            if encryption_config.get("enabled", False) or encryption_config.get("isEnabled", False):
                is_encrypted = True
            if encryption_config.get("algorithm") or encryption_config.get("keyId"):
                is_encrypted = True

        # Check for data at rest encryption
        data_at_rest = data.get("dataAtRestEncryption", {})
        if isinstance(data_at_rest, dict):
            if data_at_rest.get("enabled", False) or data_at_rest.get("isEnabled", False):
                is_encrypted = True

        return {
            "isBackupEncrypted": is_encrypted,
            "encryptionManaged": encryption_managed
        }

    except json.JSONDecodeError:
        return {"isBackupEncrypted": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEncrypted": False, "error": str(e)}
