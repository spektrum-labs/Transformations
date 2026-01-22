def transform(input):
    """
    Ensure that email filters are configured to block phishing and spam

    Parameters:
        input (dict): The JSON data containing sublime API response

    Returns:
        dict: A dictionary with the isAntiPhishingEnabled evaluation result
    """

    criteria_key = "isAntiPhishingEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check anti-phishing status
        antiphishing_enabled = False
        protection_details = {}

        # Check for anti-phishing indicators
        if 'antiphishingEnabled' in input or 'phishingProtection' in input:
            antiphishing_enabled = bool(input.get('antiphishingEnabled', input.get('phishingProtection', False)))
        elif 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            phishing_policies = [p for p in policies if 'phishing' in str(p).lower() or 'spam' in str(p).lower()]
            antiphishing_enabled = len(phishing_policies) > 0
            protection_details['phishingPolicies'] = len(phishing_policies)
        elif 'filters' in input:
            filters = input['filters'] if isinstance(input['filters'], list) else []
            antiphishing_enabled = len(filters) > 0
            protection_details['filters'] = filters
        elif 'enabled' in input:
            antiphishing_enabled = bool(input['enabled'])

        return {
            criteria_key: antiphishing_enabled,
            **protection_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
