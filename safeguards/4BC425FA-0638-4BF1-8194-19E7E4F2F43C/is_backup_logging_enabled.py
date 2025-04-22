# is_backup_logging_enabled.py

import json
    
def transform(input):
    """
    Checks whether logging is enabled and sending to SIEM if possible.
    Returns: {"isBackupLoggingEnabled": bool}
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
        logging_enabled = bool(data.get("restoreJobs", []))
        return {"isBackupLoggingEnabled": logging_enabled}

    except json.JSONDecodeError:
        return {"isBackupLoggingEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}
