# is_backup_immutable.py
import json
def transform(input):
    """
    Checks that Backup Vault Lock is active (i.e. immutable) by parsing the
    JSON response from the GetBackupVaultLockConfiguration REST API.
    Expects input to be a dict (or JSON string/bytes) of the form:
    {
      "BackupVaultName": "string",
      "BackupVaultLockConfiguration": {
        "MinRetentionDays": number,
        "MaxRetentionDays": number,
        "ChangeableForDays": number,
        "LockState": "LOCKED"|"UNLOCKED",
        "LockDate": number  # Unix ms timestamp
      }
    }
    Returns:
      {"isBackupImmutable": True}  if LockState == "LOCKED"
      {"isBackupImmutable": False} otherwise (or on error)
    """
    try:
        def _parse_input(input):
            """
            Normalize input to a Python dict.
            Accepts JSON string, bytes, or dict.
            """
            if isinstance(input, dict):
                return input
            if isinstance(input, str):
                return json.loads(input)
            if isinstance(input, (bytes, bytearray)):
                return json.loads(input.decode("utf-8"))
            raise ValueError("Input must be a dict, JSON string, or bytes")
    
        data = _parse_input(input)
        # Grab the lock configuration block
        lock_conf = data.get("BackupVaultLockConfiguration", {})
        # Determine immutability: true only in full compliance LOCKED state
        lock_state = lock_conf.get("LockState", "").upper()
        is_immutable = (lock_state == "LOCKED")
        return {"isBackupImmutable": is_immutable}
    except json.JSONDecodeError:
        return {"isBackupImmutable": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupImmutable": False, "error": str(e)}
