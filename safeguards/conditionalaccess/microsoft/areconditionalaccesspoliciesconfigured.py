def transform(input):
    """
    Check if policies exist that are configured to use real-time signals to control access to organizational resources

    Parameters:
        input (dict): The JSON data containing ms365_ca API response

    Returns:
        dict: A dictionary with the areConditionalAccessPoliciesConfigured evaluation result
    """

    criteria_key = "areConditionalAccessPoliciesConfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check for policies
        policies_configured = False
        policy_count = 0
        policy_details = {}

        # Check common policy structures
        if 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            policy_count = len(policies)
            policies_configured = policy_count > 0
            if policies_configured:
                policy_details['policies'] = policies
        elif 'policy' in input:
            policies_configured = bool(input['policy'])
            policy_count = 1 if policies_configured else 0
            policy_details['policy'] = input['policy']
        elif 'rules' in input:
            rules = input['rules'] if isinstance(input['rules'], list) else []
            policy_count = len(rules)
            policies_configured = policy_count > 0
            policy_details['rules'] = rules
        elif isinstance(input, list):
            policy_count = len(input)
            policies_configured = policy_count > 0
            policy_details['items'] = input

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
