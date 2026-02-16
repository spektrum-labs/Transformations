def transform(input):
    """
    Checks if strong authentication is required via Aquera IAM policies

    Parameters:
        input (dict): The JSON data containing Aquera policies API response

    Returns:
        dict: A dictionary with the isStrongAuthRequired evaluation result
    """

    criteria_key = "isStrongAuthRequired"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        strong_auth_required = False
        auth_details = {}

        # Check authentication policies
        policies = input.get('policies', input.get('data', input.get('value', [])))
        if isinstance(policies, list):
            auth_details['totalPolicies'] = len(policies)

            mfa_policies = []
            for policy in policies:
                auth_req = policy.get('authenticationRequirements', policy.get('mfaRequired', False))
                if auth_req and auth_req is not False:
                    mfa_policies.append(policy.get('name', policy.get('id', '')))

            auth_details['mfaPolicies'] = len(mfa_policies)
            strong_auth_required = len(mfa_policies) > 0

        # Check for authentication settings
        elif 'authenticationSettings' in input:
            settings = input['authenticationSettings']
            strong_auth_required = settings.get('mfaRequired', settings.get('strongAuthRequired', False))
            auth_details['authenticationSettings'] = settings
        elif 'mfaEnabled' in input:
            strong_auth_required = bool(input['mfaEnabled'])
            auth_details['mfaEnabled'] = input['mfaEnabled']

        return {
            criteria_key: strong_auth_required,
            **auth_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
