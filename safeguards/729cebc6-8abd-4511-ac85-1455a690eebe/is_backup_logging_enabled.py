# is_backup_logging_enabled.py

import json
import ast    
def transform(input):
    """
    Checks whether logging is enabled and sending to SIEM if possible.
    Returns: {"isBackupLoggingEnabled": bool}
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
    
        # Ensure input is a dictionary by parsing if necessary
        input = _parse_input(input)

        # Extract response safely
        input = input.get("response",input)
        input = input.get("result",input)
        input = input.get("apiResponse",input)
        data = input.get("data",input)

        if 'rows' in data:
            rows = data.get("rows",[])
            for row in rows:
                if isinstance(row,list):
                    for item in row:
                        if isinstance(item,dict):
                            if 'hasDiagnosticSettings' in item:
                                logging_enabled = True if item['hasDiagnosticSettings'] else False
                                if logging_enabled and 'logCategories' in item and item['logCategories']:
                                    return {"isBackupLoggingEnabled": True}

        return {"isBackupLoggingEnabled": False}

    except json.JSONDecodeError:
        return {"isBackupLoggingEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}
