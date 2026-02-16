def transform(input):
    """
    Checks if data retention policies are configured in Cato Networks

    Parameters:
        input (dict): The JSON data containing Cato retention policy API response

    Returns:
        dict: A dictionary with the areRetentionPoliciesConfigured evaluation result
    """

    criteria_key = "areRetentionPoliciesConfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        retention_configured = False
        policy_details = {}

        # Cato GraphQL response structure
        data = input.get('data', input)
        policy_data = data.get('policy', data)

        # Check for retention-related policies
        if 'retentionPolicies' in policy_data:
            policies = policy_data['retentionPolicies']
            if isinstance(policies, list):
                retention_configured = len(policies) > 0
                policy_details['policyCount'] = len(policies)
            elif isinstance(policies, dict):
                retention_configured = policies.get('enabled', False)
                policy_details['enabled'] = retention_configured
        elif 'dataRetention' in policy_data:
            retention = policy_data['dataRetention']
            retention_configured = bool(retention) and retention.get('enabled', False)
            policy_details['dataRetention'] = retention
        elif 'retention' in input:
            retention_configured = bool(input['retention'])
            policy_details['retention'] = input['retention']

        return {
            criteria_key: retention_configured,
            **policy_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
