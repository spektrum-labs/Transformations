def transform(input):
    """
    Evaluates if cloud firewall rules are configured and active in Zscaler ZIA.

    Checks for the presence of firewall rules and their enabled status.

    Parameters:
        input (dict): The JSON data from Zscaler ZIA firewall rules endpoint.

    Returns:
        dict: A dictionary summarizing the firewall status.
    """

    try:
        if 'response' in input:
            input = input['response']

        isFirewallEnabled = False
        rules_count = 0
        enabled_rules_count = 0

        # Get firewall rules from response
        firewall_rules = input.get('firewallRules', input.get('responseData', []))

        if isinstance(firewall_rules, list):
            rules_count = len(firewall_rules)

            if rules_count > 0:
                isFirewallEnabled = True

                # Count enabled rules
                for rule in firewall_rules:
                    state = rule.get('state', rule.get('status', '')).upper()
                    enabled = rule.get('enabled', True)

                    if state == 'ENABLED' or enabled is True:
                        enabled_rules_count += 1

        # Check for firewall policy settings
        if input.get('firewallEnabled') or input.get('cloudFirewallEnabled'):
            isFirewallEnabled = True

        firewall_info = {
            "isFirewallEnabled": isFirewallEnabled,
            "rulesCount": rules_count,
            "enabledRulesCount": enabled_rules_count
        }
        return firewall_info
    except Exception as e:
        return {"isFirewallEnabled": False, "error": str(e)}
