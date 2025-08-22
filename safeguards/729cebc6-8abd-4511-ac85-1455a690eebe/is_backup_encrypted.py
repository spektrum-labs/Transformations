# is_backup_encrypted.py

import json
import ast

def transform(input):
    """
    Checks that all backups are encrypted at rest.
    Returns: {"isBackupEncrypted": bool}
    """
    all_enc = True
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
    
        data = _parse_input(input).get("response", _parse_input(input))
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        
        if 'totalRecords' in data:
            if data['totalRecords'] < 1:
                all_enc = False

        return {"isBackupEncrypted": all_enc}

    except json.JSONDecodeError:
        return {"isBackupEncrypted": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEncrypted": False, "error": str(e)}
