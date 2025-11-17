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

        is_firewall_enabled = True if input.get('isFirewallEnabled',False) else False
        
        is_firewall_logging_enabled = True if input.get('isFirewallLoggingEnabled',False) else False

        if 'items' in input:
            is_firewall_enabled = True
            items = input['items']
            is_firewall_logging_enabled = True if len(items) > 0 else False
            
        firewall_info = {
            "isFirewallEnabled": is_firewall_enabled,
            "isFirewallLoggingEnabled": is_firewall_logging_enabled,
            "isFirewallConfigured": is_firewall_enabled and is_firewall_logging_enabled
        }
        return firewall_info
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return {"isFirewallEnabled": False, "isFirewallLoggingEnabled": is_firewall_logging_enabled,"isFirewallConfigured": is_firewall_enabled and is_firewall_logging_enabled,"error": str(e)}
        