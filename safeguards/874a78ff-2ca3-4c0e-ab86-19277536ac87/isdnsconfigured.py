import json
import ast

def transform(input):
    """
    Evaluates if DMARC, DKIM and SPF records are set up properly

    Parameters:
        input (dict): The JSON data containing Email Security information.

    Returns:
        dict: A dictionary summarizing the DMARC, DKIM and SPF records information.
    """

    is_dmarc_configured = False
    is_dkim_configured = False
    is_spf_configured = False
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

        is_dmarc_configured = True if input.get('DMARC',False) else False
            
        is_dkim_configured = True if input.get('DKIM',False) else False
            
        is_spf_configured = True if input.get('SPF',False) else False
            
        dns_info = {
            "isDMARCConfigured": is_dmarc_configured,
            "isDKIMConfigured": is_dkim_configured,
            "isSPFConfigured": is_spf_configured,
            "isDNSConfigured": is_dmarc_configured and is_dkim_configured and is_spf_configured
        }
        return dns_info
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return {"isDNSConfigured": False, "isDMARCConfigured": is_dmarc_configured,"isDKIMConfigured": is_dkim_configured,"isSPFConfigured": is_spf_configured,"error": str(e)}
        