import json
import ast

def transform(input):
    """
    Evaluates the backup status of DB instances.

    Parameters:
        input (str | dict): The JSON data containing DB Backup information. 
                            If a string is provided, it will be parsed.

    Returns:
        dict: A dictionary summarizing the DB backup information.
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

        input = _parse_input(input)

        # Extract response safely
        input = input.get("response",input)
        input = input.get("result",input)
        input = input.get("apiResponse",input)
        data = input.get("data",input)

        if 'rows' in data:
            rows = data.get("rows",[])
            if len(rows) > 0:
                return {"isBackupEnabled": True}
        
        # Construct the output
        return {"isBackupEnabled": False}

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON format."}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}
