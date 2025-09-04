import json
import ast

def transform(input):
    """
    Evaluates if email security logging is enabled

    Parameters:
        input (dict): The JSON data containing Email Security information.

    Returns:
        dict: A dictionary summarizing the email security logging information.
    """

    is_email_security_logging_enabled = False
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
        
        email_security_logging_enabled = input.get('value', [])
        if len(email_security_logging_enabled) > 0:
            is_email_security_logging_enabled = True

        email_security_logging_info = {
            "isEmailSecurityLoggingEnabled": is_email_security_logging_enabled,
            "isEmailLoggingEnabled": is_email_security_logging_enabled
        }
        return email_security_logging_info
    except Exception as e:
        return {"isEmailSecurityLoggingEnabled": False, "isEmailLoggingEnabled": False, "error": str(e)}
        