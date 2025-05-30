import json
import ast

def transform(input):
    """
    Evaluates if Firewalls are set up properly

    Parameters:
        input (dict): The JSON data containing Firewall information.

    Returns:
        dict: A dictionary summarizing the Firewall information.
    """

    is_firewall_enabled = False
    is_firewall_logging_enabled = False
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

        is_firewall_enabled = True if input.get('isFirewallEnabled',False) else False
            
        is_firewall_logging_enabled = True if input.get('isFirewallLoggingEnabled',False) else False
            
        firewall_info = {
            "isFirewallEnabled": is_firewall_enabled,
            "isFirewallLoggingEnabled": is_firewall_logging_enabled,
            "isFirewallConfigured": is_firewall_enabled and is_firewall_logging_enabled
        }
        return firewall_info
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return {"isFirewallEnabled": False, "isFirewallLoggingEnabled": is_firewall_logging_enabled,"isFirewallConfigured": is_firewall_enabled and is_firewall_logging_enabled,"error": str(e)}
        