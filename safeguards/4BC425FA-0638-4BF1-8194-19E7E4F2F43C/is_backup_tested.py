# is_backup_tested.py

import json

def transform(input):
    """
    Checks whether any backups have been tested via restore operations.
    Returns: {"isBackupTested": bool}
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                return json.loads(input)
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")
    
        data = _parse_input(input).get("response", {}).get("result", _parse_input(input))

        # No restore/test records in this payload → always False
        tested = bool(data.get("restoreJobs", []))
        return {"isBackupTested": tested}

    except json.JSONDecodeError:
        return {"isBackupTested": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}
