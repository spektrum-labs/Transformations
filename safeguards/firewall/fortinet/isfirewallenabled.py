def transform(input):
    """
    Iterates through each policy object to determine if the firewall is enabled

    Parameters:
        input (dict): The JSON data containing Fortinet firewall policy API response

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
        policy_count = 0
        enabled_count = 0
        policy_details = {}

        # Fortinet returns policies in 'results' array
        policies = input.get('results', input.get('policies', []))
        if isinstance(policies, list):
            policy_count = len(policies)
            for policy in policies:
                status = policy.get('status', '')
                if status == 'enable' or status == 'enabled' or status is True:
                    enabled_count += 1

            firewall_enabled = enabled_count > 0
            policy_details['totalPolicies'] = policy_count
            policy_details['enabledPolicies'] = enabled_count
        elif isinstance(input, list):
            policy_count = len(input)
            firewall_enabled = policy_count > 0

        return {
            criteria_key: firewall_enabled,
            **policy_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
