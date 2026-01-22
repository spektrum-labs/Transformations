def transform(input):
    """
    Review group and application access to resources.

    Parameters:
        input (dict): The JSON data containing ms365_iam API response

    Returns:
        dict: A dictionary with the areAccessReviewsConfigured evaluation result
    """

    criteria_key = "areAccessReviewsConfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check conditional access policies
        policies_configured = False
        policy_details = {}

        # Check for conditional access indicators
        if 'conditionalAccessPolicies' in input:
            policies = input['conditionalAccessPolicies'] if isinstance(input['conditionalAccessPolicies'], list) else []
            policies_configured = len(policies) > 0
            policy_details['conditionalAccessPolicies'] = len(policies)
        elif 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            policies_configured = len(policies) > 0
            policy_details['policies'] = len(policies)
        elif 'enabled' in input:
            policies_configured = bool(input['enabled'])
        elif isinstance(input, list):
            policies_configured = len(input) > 0
            policy_details['count'] = len(input)

        return {
            criteria_key: policies_configured,
            **policy_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
