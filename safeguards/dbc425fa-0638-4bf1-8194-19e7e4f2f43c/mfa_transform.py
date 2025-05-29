def transform(input):
    """
    Evaluates the MFA status for users in the organization

    Parameters:
        input (dict): The JSON data containing users information.

    Returns:
        dict: A dictionary summarizing the MFA information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
        if 'result' in input:
            input = input['result']
            
        isMFAEnforcedForUsers = False
        mfa_info = {
            "totalUsers": 0,
            "mfaEnrolledUsers": 0
        }

        if 'isMFAEnforcedForUsers' in input:
            isMFAEnforcedForUsers = input['isMFAEnforcedForUsers']
        
        if 'rawResponse' in input:
            input = input['rawResponse']
            
        if 'users' in input:
            input = input['users']
        
            mfa_enrolled = [obj for obj in input if 'isEnforcedIn2Sv' in obj and str(obj['isEnforcedIn2Sv']).lower() == "true"]
            isMFAEnforcedForUsers = True if mfa_enrolled is not None and len(mfa_enrolled) > 0 else False
            mfa_info['totalUsers'] = len(input)
            mfa_info['mfaEnrolledUsers'] = len(mfa_enrolled)

        mfa_info['isMFAEnforcedForUsers'] = isMFAEnforcedForUsers

        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}