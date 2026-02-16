def transform(input):
    """
    Checks if SASE is enabled by verifying WAN and application policies in Cato

    Parameters:
        input (dict): The JSON data containing Cato WAN/app policies API response

    Returns:
        dict: A dictionary with the isSASEEnabled evaluation result
    """

    criteria_key = "isSASEEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        sase_enabled = False
        sase_details = {}

        # Cato GraphQL response
        data = input.get('data', input)
        policy = data.get('policy', data)

        # Check WAN network policy
        wan_network = policy.get('wanNetwork', {})
        if isinstance(wan_network, dict):
            wan_policy = wan_network.get('policy', {})
            wan_enabled = wan_policy.get('enabled', False)
            sase_details['wanNetworkEnabled'] = wan_enabled
            wan_rules = wan_policy.get('rules', [])
            if isinstance(wan_rules, list):
                sase_details['wanRuleCount'] = len(wan_rules)
            if wan_enabled:
                sase_enabled = True

        # Check app policies
        app_policies = policy.get('appTenantRestriction', {})
        if isinstance(app_policies, dict):
            app_policy = app_policies.get('policy', {})
            app_enabled = app_policy.get('enabled', False)
            sase_details['appPoliciesEnabled'] = app_enabled
            if app_enabled:
                sase_enabled = True

        # Check internet firewall as SASE component
        internet_fw = policy.get('internetFirewall', {})
        if isinstance(internet_fw, dict):
            fw_policy = internet_fw.get('policy', {})
            fw_enabled = fw_policy.get('enabled', False)
            sase_details['internetFirewallEnabled'] = fw_enabled
            if fw_enabled:
                sase_enabled = True

        return {
            criteria_key: sase_enabled,
            **sase_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
