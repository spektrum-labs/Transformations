def transform(input):
    """
    Check password policies are configured and active

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the confirmPasswordPolicyEnforced evaluation result
    """

    criteria_key = "confirmPasswordPolicyEnforced"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        password_policy_enforced = False
        policy_details = {}

        # Check for password policies array (Saviynt getPasswordPolicy response)
        if 'passwordpolicies' in input:
            policies = input['passwordpolicies']
            if isinstance(policies, list):
                # Check if there are active policies
                active_policies = [p for p in policies if p.get('status', '').lower() in ['active', 'enabled', '1', 'true'] or p.get('enabled', False)]
                if len(active_policies) == 0 and len(policies) > 0:
                    # If no status field, assume policies are active if they exist
                    active_policies = policies
                password_policy_enforced = len(active_policies) > 0
                policy_details['policyCount'] = len(active_policies)
        elif 'passwordPolicies' in input:
            policies = input['passwordPolicies']
            if isinstance(policies, list):
                password_policy_enforced = len(policies) > 0
                policy_details['policyCount'] = len(policies)
        elif 'passwordPolicyEnforced' in input:
            password_policy_enforced = bool(input['passwordPolicyEnforced'])

        return {
            criteria_key: password_policy_enforced,
            **policy_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
