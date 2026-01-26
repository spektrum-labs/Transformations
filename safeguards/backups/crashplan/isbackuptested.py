# isbackuptested.py - CrashPlan

import json
import ast
from datetime import datetime, timedelta

def transform(input):
    """
    Analyzes restore history to verify backup testing activities have been performed.
    Returns True if restore operations have been performed recently (within 90 days).

    Parameters:
        input (dict): The JSON data from CrashPlan listRestoreHistory endpoint.

    Returns:
        dict: A dictionary indicating if backups have been tested.
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

        # Get restore history
        restores = (
            data.get("restores", []) or
            data.get("restoreHistory", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        total_restores = 0
        recent_restores = 0
        successful_restores = 0
        last_restore_date = None

        # Calculate 90-day threshold
        now = datetime.utcnow()
        threshold = now - timedelta(days=90)

        if isinstance(restores, list):
            total_restores = len(restores)

            for restore in restores:
                # Check restore date
                restore_date_str = restore.get("doneDate") or restore.get("startDate") or restore.get("creationDate")

                if restore_date_str:
                    try:
                        # Parse ISO format date
                        if "T" in str(restore_date_str):
                            restore_date = datetime.fromisoformat(restore_date_str.replace("Z", "+00:00").replace("+00:00", ""))
                        else:
                            restore_date = datetime.strptime(str(restore_date_str)[:10], "%Y-%m-%d")

                        # Track last restore date
                        if last_restore_date is None or restore_date > last_restore_date:
                            last_restore_date = restore_date

                        # Check if within threshold
                        if restore_date >= threshold:
                            recent_restores += 1
                    except:
                        pass

                # Check restore status
                status = restore.get("status", "").lower()
                if status in ["done", "complete", "completed", "success", "successful"]:
                    successful_restores += 1

        elif data.get("totalCount"):
            total_restores = data.get("totalCount", 0)

        # Backup is considered tested if there are recent successful restores
        is_tested = recent_restores > 0 or (total_restores > 0 and successful_restores > 0)

        result = {
            "isBackupTested": is_tested,
            "totalRestores": total_restores,
            "recentRestores": recent_restores,
            "successfulRestores": successful_restores
        }

        if last_restore_date:
            result["lastRestoreDate"] = last_restore_date.isoformat()

        return result

    except json.JSONDecodeError:
        return {"isBackupTested": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}
