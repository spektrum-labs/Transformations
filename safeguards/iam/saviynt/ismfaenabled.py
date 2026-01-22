def transform(input):
    """
    Check if MFA is enabled in org security settings

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the isMFAEnabled evaluation result
    """

    criteria_key = "isMFAEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        mfa_enabled = False
        mfa_details = {}

        # Check organization security settings for MFA
        if 'organization' in input:
            org = input['organization']
            mfa_enabled = bool(org.get('mfaEnabled', False))
            mfa_details['organizationMfaEnabled'] = mfa_enabled
        elif 'securitySettings' in input:
            settings = input['securitySettings']
            mfa_enabled = bool(settings.get('mfaEnabled', False))
            mfa_details['securitySettingsMfaEnabled'] = mfa_enabled
        elif 'mfaEnabled' in input:
            mfa_enabled = bool(input['mfaEnabled'])

        return {
            criteria_key: mfa_enabled,
            **mfa_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
