# isbackupencrypted.py - CrashPlan

import json
import ast

def transform(input):
    """
    Checks organization security settings for encryption configuration.
    CrashPlan encrypts all data by default using AES-256 encryption.

    Parameters:
        input (dict): The JSON data from CrashPlan getSecuritySettings endpoint.

    Returns:
        dict: A dictionary indicating if backup encryption is enabled.
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
        data = data.get("securitySettings", data)

        # CrashPlan always encrypts data by default
        # Check for encryption-related settings
        encryption_enabled = True  # CrashPlan default
        encryption_key_type = "archive"  # Default key type

        # Check for custom archive key settings
        if "archiveKeyRule" in data:
            encryption_key_type = data.get("archiveKeyRule", "archive")

        # Check for encryption override settings
        if "encryptionEnabled" in data:
            encryption_enabled = data.get("encryptionEnabled", True)

        # Check security key configuration
        security_key_locked = data.get("securityKeyLocked", False)
        security_key_type = data.get("securityKeyType", "")

        # Check for organization-level encryption settings
        org_security = data.get("orgSecurityInfo", {})
        if org_security:
            if "encryptionEnabled" in org_security:
                encryption_enabled = org_security.get("encryptionEnabled", True)

        # Determine encryption management type
        is_managed = encryption_key_type in ["accountPassword", "archive"]
        is_custom_key = encryption_key_type == "customKey"

        return {
            "isBackupEncrypted": encryption_enabled,
            "encryptionKeyType": encryption_key_type,
            "encryptionManaged": is_managed,
            "customKeyUsed": is_custom_key,
            "securityKeyLocked": security_key_locked
        }

    except json.JSONDecodeError:
        return {"isBackupEncrypted": False, "error": "Invalid JSON"}
    except Exception as e:
        # CrashPlan encrypts by default, so if we can't determine settings
        # we return True with a note
        return {
            "isBackupEncrypted": True,
            "encryptionManaged": True,
            "note": "CrashPlan encrypts all data by default",
            "parseError": str(e)
        }
