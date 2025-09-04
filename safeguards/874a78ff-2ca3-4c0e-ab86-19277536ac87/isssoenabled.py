import json
import ast

def transform(input):
    """
    Evaluates if SSO is enabled for the given Mail Provider

    Parameters:
        input (dict): The JSON data containing Mail Provider information.

    Returns:
        dict: A dictionary summarizing the SSO information.
    """

    try:
        # Initialize variables
        isSSOEnabled = False

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

            return input
                    
        # Initialize data
        if 'response' in input:
            input = _parse_input(input['response'])

        if 'result' in input:
            input = _parse_input(input['result'])

        if 'rawResponse' in input:
            input = _parse_input(input['rawResponse'])

        providers = input.get('value', [])
        if len(providers) > 0:
            isSSOEnabled = True

        sso_info = {
            "isSSOEnabled": isSSOEnabled,
            "providers": providers
        }
        return sso_info
    except Exception as e:
        return {"isSSOEnabled": False, "providers": [], "error": str(e)}
        