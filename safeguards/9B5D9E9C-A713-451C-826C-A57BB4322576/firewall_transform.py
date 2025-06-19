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
    is_internet_firewall_enabled = False
    is_wan_network_enabled = False
    internet_firewall_rules = []
    wan_network_rules = []
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

        if 'firewall' in input:
            firewall_data = _parse_input(input['firewall'])
        else:
            firewall_data = input

        if 'wanNetwork' in input:
            wan_network_data = _parse_input(input['wanNetwork'])
        else:
            wan_network_data = input

        is_firewall_enabled = True if input.get('isFirewallEnabled',False) else False
            
        if 'data' in firewall_data:
            firewall_data = _parse_input(firewall_data['data'])
            if 'policy' in firewall_data:
                firewall_data = _parse_input(firewall_data['policy'])
                #Internet Firewall
                if 'internetFirewall' in firewall_data:
                    firewall_policy = _parse_input(firewall_data['internetFirewall'])
                    if 'policy' in firewall_policy:
                        firewall_policy = _parse_input(firewall_policy['policy'])
                        if 'enabled' in firewall_policy:
                            is_internet_firewall_enabled = True if firewall_policy.get('enabled',False) else False
                        if 'rules' in firewall_policy:
                            #List of rules
                            internet_firewall_rules_raw = firewall_policy['rules']
                            for rule in internet_firewall_rules_raw:
                                if 'rule' in rule and 'name' in rule['rule']:
                                    internet_firewall_rules.append(rule['rule']['name'])
        #WAN Network
        if 'data' in wan_network_data:
            wan_network_data = _parse_input(wan_network_data['data'])
            if 'policy' in wan_network_data:
                wan_network_data = _parse_input(wan_network_data['policy'])                
                if 'wanNetwork' in wan_network_data:
                    wan_network_policy = _parse_input(wan_network_data['wanNetwork'])
                    if 'policy' in wan_network_policy:
                        wan_network_policy = _parse_input(wan_network_policy['policy'])
                        if 'enabled' in wan_network_policy:
                            is_wan_network_enabled = True if wan_network_policy.get('enabled',False) else False
                        if 'rules' in wan_network_policy:
                            wan_network_rules_raw = wan_network_policy['rules']
                            for rule in wan_network_rules_raw:
                                if 'rule' in rule and 'name' in rule['rule']:
                                    wan_network_rules.append(rule['rule']['name'])

        is_firewall_logging_enabled = True if input.get('isFirewallLoggingEnabled',False) else False
        
        #Audit Logs
        if 'data' in input:
            input = _parse_input(input['data'])
            if 'auditFeed' in input:
                audit_logs_raw = _parse_input(input['auditFeed'])
                if 'fetchedCount' in audit_logs_raw:
                    is_firewall_logging_enabled = True if audit_logs_raw.get('fetchedCount',0) > 0 else False

        firewall_info = {
            "isFirewallEnabled": is_firewall_enabled or (is_internet_firewall_enabled and is_wan_network_enabled),
            "isFirewallLoggingEnabled": is_firewall_logging_enabled,
            "isFirewallConfigured": True if len(internet_firewall_rules) > 0 or len(wan_network_rules) > 0 else False,
            "internetFirewallRules": internet_firewall_rules,
            "wanNetworkRules": wan_network_rules
        }
        return firewall_info
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return {"isFirewallEnabled": False, "isFirewallLoggingEnabled": is_firewall_logging_enabled,"isFirewallConfigured": is_firewall_enabled and is_firewall_logging_enabled,"error": str(e)}
        