def transform(input):
    """
    Checks if Azure Firewall is enabled and provisioned

    Parameters:
        input (dict): The JSON data containing Azure Firewall status API response

    Returns:
        dict: A dictionary with the isFirewallEnabled evaluation result
    """

    criteria_key = "isFirewallEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        firewall_enabled = False
        firewall_details = {}

        # Azure Firewall response structure
        properties = input.get('properties', input)
        provisioning_state = properties.get('provisioningState', '')
        threat_intel_mode = properties.get('threatIntelMode', '')

        if provisioning_state.lower() == 'succeeded':
            firewall_enabled = True
            firewall_details['provisioningState'] = provisioning_state

        if threat_intel_mode:
            firewall_details['threatIntelMode'] = threat_intel_mode

        # Check for firewall policy association
        firewall_policy = properties.get('firewallPolicy', {})
        if firewall_policy:
            firewall_details['hasFirewallPolicy'] = True
            firewall_details['firewallPolicyId'] = firewall_policy.get('id', '')

        # Check IP configurations
        ip_configs = properties.get('ipConfigurations', [])
        if isinstance(ip_configs, list):
            firewall_details['ipConfigurationCount'] = len(ip_configs)

        return {
            criteria_key: firewall_enabled,
            **firewall_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
