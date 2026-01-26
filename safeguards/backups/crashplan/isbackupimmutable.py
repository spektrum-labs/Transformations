# isbackupimmutable.py - CrashPlan

import json
import ast

def transform(input):
    """
    Checks for legal hold policies that enforce data retention and immutability.
    CrashPlan supports legal hold which prevents data deletion.

    Parameters:
        input (dict): The JSON data from CrashPlan listLegalHolds endpoint.

    Returns:
        dict: A dictionary indicating if backup immutability is configured.
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

        # Get legal holds data
        legal_holds = (
            data.get("legalHolds", []) or
            data.get("holds", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        total_holds = 0
        active_holds = 0
        hold_names = []

        if isinstance(legal_holds, list):
            total_holds = len(legal_holds)

            for hold in legal_holds:
                # Check if hold is active
                is_active = hold.get("active", True)  # Default to active if not specified
                status = hold.get("status", "").lower()

                if is_active or status in ["active", "enabled"]:
                    active_holds += 1
                    hold_name = hold.get("name", hold.get("holdName", ""))
                    if hold_name:
                        hold_names.append(hold_name)

        elif data.get("totalCount"):
            total_holds = data.get("totalCount", 0)
            active_holds = total_holds

        # Immutability is considered enabled if legal holds are in place
        is_immutable = active_holds > 0

        return {
            "isBackupImmutable": is_immutable,
            "totalLegalHolds": total_holds,
            "activeLegalHolds": active_holds,
            "holdNames": hold_names[:10],  # Limit to first 10 names
            "retentionLockEnabled": is_immutable
        }

    except json.JSONDecodeError:
        return {"isBackupImmutable": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupImmutable": False, "error": str(e)}
