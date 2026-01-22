def transform(input):
    """
    Validate that MFA is enforced for all users and what authTypesAllowed

    Parameters:
        input (dict): The JSON data containing googlemfa API response

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

        # Check MFA/Auth status
        mfa_enforced = False
        total_users = 0
        enrolled_users = 0
        auth_details = {}

        # Check for user arrays with MFA status
        if 'users' in input:
            users = input['users'] if isinstance(input['users'], list) else []
            total_users = len(users)
            enrolled_users = len([u for u in users if u.get('is_enrolled') or u.get('mfaEnabled') or u.get('twoFactorEnabled')])
            mfa_enforced = enrolled_users > 0 and (enrolled_users / total_users >= 0.9) if total_users > 0 else False
        elif 'mfaEnabled' in input or 'mfaEnforced' in input:
            mfa_enforced = bool(input.get('mfaEnabled', input.get('mfaEnforced', False)))
        elif 'authTypes' in input or 'authenticationMethods' in input:
            auth_types = input.get('authTypes', input.get('authenticationMethods', []))
            mfa_enforced = len(auth_types) > 1 or 'mfa' in str(auth_types).lower()
            auth_details['authTypes'] = auth_types
        elif 'required' in input or 'enforced' in input:
            mfa_enforced = bool(input.get('required', input.get('enforced', False)))

        return {
            criteria_key: mfa_enforced,
            "totalUsers": total_users,
            "enrolledUsers": enrolled_users,
            **auth_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
