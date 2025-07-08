import json
import ast

def transform(input):
    """
    Evaluates if Network Security is set up properly

    Parameters:
        input (dict): The JSON data containing Network Security information.

    Returns:
        dict: A dictionary summarizing the Network Security information.
    """

    is_continuous_discovery_enabled = False
    try:
        # Initialize counters
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
        
        if 'response' in input:
            input = _parse_input(input['response'])
        if 'result' in input:
            input = _parse_input(input['result'])

        is_continuous_discovery_enabled = True if input.get('isContinuousDiscoveryEnabled',False) else False
        if not is_continuous_discovery_enabled:
            is_continuous_discovery_enabled = True if input.get('devices',False) else False 
            
        network_info = {
            "isContinuousDiscoveryEnabled": is_continuous_discovery_enabled
        }
        return network_info
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return {"isContinuousDiscoveryEnabled": False,"error": str(e)}
        