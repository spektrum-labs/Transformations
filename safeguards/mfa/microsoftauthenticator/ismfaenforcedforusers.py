def transform(input):
    """
    Checks if MFA is enforced for users via Microsoft Authenticator policies

    Parameters:
        input (dict): The JSON data containing Microsoft authentication methods policy API response

    Returns:
        dict: A dictionary with the isMFAEnforcedForUsers evaluation result
    """

    criteria_key = "isMFAEnforcedForUsers"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        mfa_enforced = False
        mfa_details = {}

        # Microsoft Graph authentication methods policy response
        auth_method_configs = input.get('authenticationMethodConfigurations', [])
        if isinstance(auth_method_configs, list):
            for config in auth_method_configs:
                method_id = config.get('id', '')
                state = config.get('state', '')

                if 'microsoftAuthenticator' in method_id.lower() or method_id == 'MicrosoftAuthenticator':
                    mfa_details['microsoftAuthenticatorState'] = state
                    if state.lower() == 'enabled':
                        mfa_enforced = True

                    # Check target users
                    include_targets = config.get('includeTargets', [])
                    if isinstance(include_targets, list):
                        all_users = any(t.get('targetType') == 'group' and t.get('id') == 'all_users' for t in include_targets)
                        mfa_details['targetAllUsers'] = all_users

            mfa_details['totalAuthMethods'] = len(auth_method_configs)
            enabled_methods = [c for c in auth_method_configs if c.get('state', '').lower() == 'enabled']
            mfa_details['enabledMethods'] = len(enabled_methods)

        # Fallback: check for registration enforcement
        elif 'registrationEnforcement' in input:
            enforcement = input['registrationEnforcement']
            mfa_enforced = bool(enforcement)
            mfa_details['registrationEnforcement'] = enforcement

        return {
            criteria_key: mfa_enforced,
            **mfa_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
