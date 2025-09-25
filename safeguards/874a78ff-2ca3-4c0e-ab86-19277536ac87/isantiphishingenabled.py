import json
import ast
def transform(input):
    """
    Evaluates the MFA status for  given IDP

    Parameters:
        input (dict): The JSON data containing IDP information.

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
                    #input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
                    
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        input = _parse_input(input)
        if 'response' in input:
            input = _parse_input(input['response'])
        if 'result' in input:
            input = _parse_input(input['result'])
            if 'apiResponse' in input:
                input = _parse_input(input['apiResponse'])
            if 'result' in input:
                input = _parse_input(input['result'])         
        
        #Get Configuration Policies
        if 'Output' in input:
            input = _parse_input(input['Output'])
        if 'policies' in input:
            policies = input['policies']
        else:
            policies = []

        if isinstance(policies, dict):
            policies = [policies]
            
        matching_values = [
            policy for policy in policies if policy.get("Enabled") is True
        ]
        
        isAntiPhishingEnabled = len(matching_values) > 0

        policy_info = {
            "isAntiPhishingEnabled": isAntiPhishingEnabled,
            "policyDetails": matching_values
        }
        return policy_info
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}
        