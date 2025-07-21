def transform(input):
    """
    Evaluates the MFA status for  given IDP

    Parameters:
        input (dict): The JSON data containing IDP information.

    Returns:
        dict: A dictionary summarizing the MFA information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
            
        if 'authenticationMethodConfigurations' in input:
            mfa_enrolled = [{"id": obj['id'] if 'id' in obj else '', "state": obj['state'] if 'state' in obj else 'enabled', "includeTargets": obj['includeTargets'] if 'includeTargets' in obj else []} for obj in input['authenticationMethodConfigurations'] if 'state' in obj and str(obj['state']).lower() == "enabled"]
        else:
            mfa_enrolled = []
        mfa_info = {
            "isMFAEnforcedForUsers": True if mfa_enrolled is not None and len(mfa_enrolled) > 0 else False,
            "mfaEnrollmentPolicy": mfa_enrolled
        }
        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "mfaEnrollmentPolicy": [], "error": str(e)}
        