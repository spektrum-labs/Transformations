# isbackupenabled.py - Rubrik

import json
import ast

def transform(input):
    """
    Evaluates whether backups are enabled on Rubrik.
    Counts total snapshots across all protected objects.
    Returns True if snapshot count is greater than 0.

    Parameters:
        input (dict): The JSON data from Rubrik listSnapshots endpoint.

    Returns:
        dict: A dictionary indicating if backups are enabled.
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

        # Check for snapshots
        snapshots = (
            data.get("snapshots", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        total_snapshots = 0

        if isinstance(snapshots, list):
            total_snapshots = len(snapshots)
        elif data.get("total"):
            total_snapshots = data.get("total", 0)

        is_backup_enabled = total_snapshots > 0

        return {
            "isBackupEnabled": is_backup_enabled,
            "totalSnapshots": total_snapshots
        }

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}
