import json
import ast

def transform(input):
    """
    Evaluates if MFA is enforced/enabled for the current Email Security tenant

    Parameters:
        input (dict): The JSON data containing authentication policy information.

    Returns:
        dict: A dictionary summarizing the MFA information.
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
        

        # Initialize counters
        if 'response' in input:
            input = _parse_input(input['response'])
        if 'result' in input:
            input = _parse_input(input['result'])
        if 'rawResponse' in input:
            input = _parse_input(input['rawResponse'])

        isMFAEnforcedForUsers = False
        mfa_info = {
            "mfaTypes": []
        }

        if 'isMFAEnforcedForUsers' in input:
            isMFAEnforcedForUsers = input['isMFAEnforcedForUsers']
            
        if 'authenticationMethodConfigurations' in input:
            mfa_info['mfaTypes'] = [obj for obj in input['authenticationMethodConfigurations'] if 'state' in obj and str(obj['state']).lower() == "enabled"]
            isMFAEnforcedForUsers = True if mfa_info['mfaTypes'] is not None and len(mfa_info['mfaTypes']) > 0 else False

        mfa_info['isMFAEnforcedForUsers'] = isMFAEnforcedForUsers

        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}
        