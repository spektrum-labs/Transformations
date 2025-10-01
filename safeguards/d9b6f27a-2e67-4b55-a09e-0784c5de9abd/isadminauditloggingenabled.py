import json
import ast

def transform(input):
    """
    Evaluates if admin audit logging is enabled

    Parameters:
        input (dict): The JSON data containing admin audit log information.

    Returns:
        dict: A dictionary summarizing the admin audit log information.
    """

    criteria_key_name = "isAdminAuditLoggingEnabled"
    criteria_key_result = False

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
                
        # Initialize data
        if 'response' in input:
            input = _parse_input(input['response'])
        if 'result' in input:
            input = _parse_input(input['result'])
        if 'rawResponse' in input:
            input = _parse_input(input['rawResponse'])

	    # log entries returned as objects in value
        # we expect at least one entry in the log
        value_count = input.get('value', [])
        if len(value_count) > 0:
            criteria_key_result = True

        transformed_data = {
            criteria_key_name: criteria_key_result
        }
        return transformed_data
    except Exception as e:
        return {criteria_key_name: False, "error": str(e)}