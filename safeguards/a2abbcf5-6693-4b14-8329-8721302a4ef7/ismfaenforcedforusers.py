def transform(input):
    """
    Evaluates the MFA status for users in the organization

    Parameters:
        input (dict): The JSON data containing users information.

    Returns:
        dict: A dictionary summarizing the MFA information.
    """
    users = []
    mfa_info = {
        "totalUsers": 0,
        "mfaEnrolledUsers": 0,
        "isMFAEnforcedForUsers": True,
        "offendingUsers": []
    }
    try:
        #Loop through users to make sure they are enrolled in MFA
        isMFAEnforcedForUsers = True
        if 'metadata' in input:
            metadata = input['metadata']
            if 'total_objects' in metadata:
                try:
                    mfa_info['totalUsers'] = int(metadata['total_objects'])
                except:
                    mfa_info['totalUsers'] = metadata['total_objects']

        if 'response' in input:
            input = input['response']
        for user in input:
            if 'is_enrolled' in user:
                if str(user['is_enrolled']).lower() == "true":
                    mfa_info['mfaEnrolledUsers'] += 1
                else:
                    if 'status' in user:
                        #Check if the user is active only
                        if str(user['status']).lower() == "active":
                            users.append(user)
                            isMFAEnforcedForUsers = False

        mfa_info['isMFAEnforcedForUsers'] = isMFAEnforcedForUsers
        mfa_info['offendingUsers'] = users
        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False,"error": str(e)}
    