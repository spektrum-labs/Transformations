def transform(input):
    """
    Validate strong auth (MFA) is required

    Parameters:
        input (dict): The JSON data containing Saviynt API response

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

        # Check organization security settings
        if 'organization' in input:
            org = input['organization']
            strong_auth_required = bool(org.get('strongAuthRequired', org.get('mfaRequired', False)))
            auth_details['organizationStrongAuth'] = strong_auth_required
        elif 'securitySettings' in input:
            settings = input['securitySettings']
            strong_auth_required = bool(settings.get('strongAuthRequired', settings.get('mfaRequired', False)))
            auth_details['securitySettingsStrongAuth'] = strong_auth_required
        elif 'strongAuthRequired' in input:
            strong_auth_required = bool(input['strongAuthRequired'])
        elif 'mfaRequired' in input:
            strong_auth_required = bool(input['mfaRequired'])

        return {
            criteria_key: strong_auth_required,
            **auth_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
