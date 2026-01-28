def transform(input):
    """
    Validates that MFA/2FA is enforced for all users in Keeper enterprise.

    Parameters:
        input (dict): The JSON data from Keeper enterprise-user command response

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
        if 'data' in input:
            input = input['data']

        mfa_required = False
        mfa_details = {
            "totalUsers": 0,
            "mfaEnabledUsers": 0,
            "mfaEnforcedPolicy": False
        }

        # Check for global MFA enforcement policy
        if 'mfa_required' in input or 'two_factor_required' in input:
            mfa_required = bool(input.get('mfa_required', input.get('two_factor_required', False)))
            mfa_details["mfaEnforcedPolicy"] = mfa_required

        # Check enforcement policies
        if 'enforcement' in input:
            enforcement = input['enforcement']
            if isinstance(enforcement, dict):
                mfa_required = enforcement.get('require_two_factor', False) or \
                               enforcement.get('mfa_required', False) or \
                               enforcement.get('two_factor_authentication', False)
                mfa_details["mfaEnforcedPolicy"] = mfa_required

        # Check user-level MFA status
        users = input.get('users', input.get('data', []))
        if isinstance(users, list):
            mfa_details["totalUsers"] = len(users)
            mfa_enabled_count = 0

            for user in users:
                if isinstance(user, dict):
                    user_mfa = user.get('two_factor_enabled', False) or \
                               user.get('mfa_enabled', False) or \
                               user.get('twoFactorAuthentication', False)
                    if user_mfa:
                        mfa_enabled_count += 1

            mfa_details["mfaEnabledUsers"] = mfa_enabled_count

            # If all users have MFA enabled, consider it required
            if mfa_details["totalUsers"] > 0 and mfa_enabled_count == mfa_details["totalUsers"]:
                mfa_required = True

        # Check for MFA status in mfaStatus response
        if 'mfaStatus' in input:
            mfa_status = input['mfaStatus']
            if isinstance(mfa_status, dict):
                mfa_required = mfa_status.get('enforced', False) or mfa_status.get('required', False)
            elif isinstance(mfa_status, list):
                # Count users with MFA
                mfa_enabled = [u for u in mfa_status if isinstance(u, dict) and u.get('mfa_enabled', False)]
                mfa_required = len(mfa_enabled) == len(mfa_status) if mfa_status else False

        return {
            criteria_key: mfa_required,
            **mfa_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
