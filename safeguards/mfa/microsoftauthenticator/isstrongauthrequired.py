def transform(input):
    """
    Checks if strong authentication (phishing-resistant) is required via conditional access

    Parameters:
        input (dict): The JSON data containing Microsoft authentication strengths and conditional access API response

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

        # Check authentication strengths (merged response)
        strengths = input.get('authenticationStrengths', input.get('value', []))
        if isinstance(strengths, dict):
            strengths = strengths.get('apiResponse', strengths).get('value', [])

        if isinstance(strengths, list):
            phishing_resistant = [s for s in strengths if 'phishingResistant' in s.get('id', '').lower() or s.get('requirementsSatisfied', '') == 'mfa']
            auth_details['totalStrengths'] = len(strengths)
            auth_details['phishingResistantPolicies'] = len(phishing_resistant)

        # Check conditional access policies (merged response)
        ca_policies = input.get('conditionalAccessPolicies', {})
        if isinstance(ca_policies, dict):
            ca_data = ca_policies.get('apiResponse', ca_policies)
            policies = ca_data.get('value', [])
        else:
            policies = input.get('value', [])

        if isinstance(policies, list):
            mfa_policies = []
            for policy in policies:
                state = policy.get('state', '')
                grant_controls = policy.get('grantControls', {})
                if isinstance(grant_controls, dict):
                    built_in = grant_controls.get('builtInControls', [])
                    auth_strength = grant_controls.get('authenticationStrength', {})

                    if 'mfa' in built_in or auth_strength:
                        if state.lower() == 'enabled':
                            mfa_policies.append(policy.get('displayName', ''))
                            strong_auth_required = True

            auth_details['mfaConditionalAccessPolicies'] = len(mfa_policies)

        return {
            criteria_key: strong_auth_required,
            **auth_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
