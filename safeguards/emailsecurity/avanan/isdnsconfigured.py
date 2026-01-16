import json
import ast

def transform(input):
    """
    Evaluates if DMARC, DKIM and SPF records are set up properly.
    
    Note: Avanan does not provide DNS data via API.
    This expects DNS data from an external DNS lookup source.

    Parameters:
        input (dict): The JSON data containing DNS information.

    Returns:
        dict: A dictionary summarizing the DMARC, DKIM and SPF records information.
    """

    is_dmarc_configured = False
    is_dkim_configured = False
    is_spf_configured = False
    
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
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

        # Check for DMARC configuration
        dmarc_data = input.get('DMARC', input.get('dmarc', None))
        if dmarc_data:
            is_dmarc_configured = True
            # Check for policy enforcement level
            if isinstance(dmarc_data, dict):
                policy = dmarc_data.get('policy', dmarc_data.get('p', ''))
                if policy.lower() in ['none', '']:
                    is_dmarc_configured = False  # DMARC exists but not enforcing
        
        # Check for DKIM configuration
        dkim_data = input.get('DKIM', input.get('dkim', None))
        if dkim_data:
            is_dkim_configured = True
            
        # Check for SPF configuration
        spf_data = input.get('SPF', input.get('spf', None))
        if spf_data:
            is_spf_configured = True
            
        dns_info = {
            "isDMARCConfigured": is_dmarc_configured,
            "isDKIMConfigured": is_dkim_configured,
            "isSPFConfigured": is_spf_configured,
            "isDNSConfigured": is_dmarc_configured and is_dkim_configured and is_spf_configured
        }
        return dns_info
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return {
            "isDNSConfigured": False, 
            "isDMARCConfigured": is_dmarc_configured, 
            "isDKIMConfigured": is_dkim_configured, 
            "isSPFConfigured": is_spf_configured, 
            "error": str(e)
        }

