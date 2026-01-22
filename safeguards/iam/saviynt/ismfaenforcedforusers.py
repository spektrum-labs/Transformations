def transform(input):
    """
    Check if MFA is enforced for all users in the organization

    Parameters:
        input (dict): The JSON data containing Saviynt API response

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
        enforcement_details = {}

        # Check organization settings for MFA enforcement
        if 'organization' in input:
            org = input['organization']
            mfa_enforced = bool(org.get('mfaEnforced', False))
            enforcement_details['organizationMfaEnforced'] = mfa_enforced
        elif 'securitySettings' in input:
            settings = input['securitySettings']
            mfa_enforced = bool(settings.get('mfaEnforced', settings.get('enforceMFA', False)))
            enforcement_details['securitySettingsMfaEnforced'] = mfa_enforced
        elif 'mfaEnforced' in input:
            mfa_enforced = bool(input['mfaEnforced'])

        return {
            criteria_key: mfa_enforced,
            **enforcement_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
