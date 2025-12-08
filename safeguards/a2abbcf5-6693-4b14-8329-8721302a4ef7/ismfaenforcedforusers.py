def transform(input):
    """
    Evaluates the MFA status for users in the organization

    Parameters:
        input (dict): The JSON data containing users information.

    Returns:
        dict: A dictionary summarizing the MFA information.
    """
    mfa_info = {
        "totalUsers": 0,
        "mfaEnrolledUsers": 0,
        "isMFAEnforcedForUsers": True
    }
    try:
        #Loop through users to make sure they are enrolled in MFA
        isMFAEnforcedForUsers = True
        if 'metadata' in input:
            metadata = input['metadata']
            if 'total_objects' in metadata:
                mfa_info['totalUsers'] = metadata['total_objects']

        if 'response' in input:
            input = input['response']
        for user in input:
            if 'is_enrolled' in user:
                if str(user['is_enrolled']).lower() == "true":
                    mfa_info['mfaEnrolledUsers'] += 1
                else:
                    isMFAEnforcedForUsers = False

        mfa_info['isMFAEnforcedForUsers'] = isMFAEnforcedForUsers
        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False,"error": str(e)}
    