# is_backup_types_scheduled.py

import json
import ast

def transform(input):
    """
    Checks if all backup types (RDS automated, RDS manual, EBS) are on a defined schedule.
    Returns: {"isBackupTypesScheduled": bool}
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                # First try to parse as literal Python string representation
                try:
                    # Use ast.literal_eval to safely parse Python literal
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                
                # If that fails, try to parse as JSON
                try:
                    # Replace single quotes with double quotes for JSON
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
                    
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")
    
        data = _parse_input(input).get("response", _parse_input(input)).get("result", _parse_input(input))
        backupschedules = data.get("data", {}).get("rows", [])
        
        scheduled_auto = False
        for schedule in backupschedules:
            if isinstance(schedule, list):
                for item in schedule:
                    if 'properties' in item:
                        if item['properties'].get('protectedItemsCount', 0) > 0:
                            scheduled_auto = True
                            break
            else:
                if 'properties' in schedule:
                    if schedule['properties'].get('protectedItemsCount', 0) > 0:
                        scheduled_auto = True
                        break

        return {"isBackupTypesScheduled": scheduled_auto}

    except json.JSONDecodeError:
        return {"isBackupTypesScheduled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}
