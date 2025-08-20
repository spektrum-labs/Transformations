# is_backup_tested.py

import json
import ast

def transform(input):
    """
    Checks whether any backups have been tested via restore operations.
    Returns: {"isBackupTested": bool}
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
    
        # Get the response from the input
        response = _parse_input(input)
        result = response.get("result",response)
        data = result.get("apiResponse", result)

        # Check if any event is a DBInstance restore operation
        is_backup_tested = False
        if 'totalRecords' in data:
            is_backup_tested = data.get("totalRecords", 0) > 0
        else:
            if 'data' in data:
                data = data.get("rows", [])
                is_backup_tested = len(data) > 0
        
        return {"isBackupTested": is_backup_tested}

    except json.JSONDecodeError:
        return {"isBackupTested": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}
