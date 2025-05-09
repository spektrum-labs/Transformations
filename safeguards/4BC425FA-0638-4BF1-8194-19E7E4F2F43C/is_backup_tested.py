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
    
        # Get the response from the input
        response = _parse_input(input)
        result = response.get("result",response)
        resource_members = result.get("apiResponse", result).get("LookupEventsResponse", {}).get("LookupEventsResult", {}).get("Events", {}).get("member", {}).get("Resources", {}).get("member", [])

        # Check if any event is a DBInstance restore operation
        is_backup_tested = False
        for resource_member in resource_members:
            resource_type = resource_member.get("ResourceType", "")
            if "dbinstance" in resource_type.lower():
                # Check if the event has values or items
                is_backup_tested = True
                break
        
        return {"isBackupTested": is_backup_tested}

    except json.JSONDecodeError:
        return {"isBackupTested": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}
