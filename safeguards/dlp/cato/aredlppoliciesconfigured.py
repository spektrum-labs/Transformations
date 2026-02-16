def transform(input):
    """
    Checks if DLP policies are configured in Cato Networks

    Parameters:
        input (dict): The JSON data containing Cato DLP policy API response

    Returns:
        dict: A dictionary with the areDLPPoliciesConfigured evaluation result
    """

    criteria_key = "areDLPPoliciesConfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        policies_configured = False
        policy_count = 0
        policy_details = {}

        # Cato GraphQL response: data.policy.dlp.policy
        data = input.get('data', input)
        policy_data = data.get('policy', data)
        dlp_data = policy_data.get('dlp', policy_data)
        dlp_policy = dlp_data.get('policy', dlp_data)

        if isinstance(dlp_policy, dict):
            enabled = dlp_policy.get('enabled', False)
            rules = dlp_policy.get('rules', [])
            policy_count = len(rules) if isinstance(rules, list) else 0
            policies_configured = enabled and policy_count > 0
            policy_details['enabled'] = enabled
            policy_details['ruleCount'] = policy_count
        elif 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            policy_count = len(policies)
            policies_configured = policy_count > 0
        elif isinstance(input, list):
            policy_count = len(input)
            policies_configured = policy_count > 0

        return {
            criteria_key: policies_configured,
            "policyCount": policy_count,
            **policy_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
