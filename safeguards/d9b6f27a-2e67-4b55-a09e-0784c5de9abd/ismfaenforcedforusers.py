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
            
        mfa_enrolled = [obj for obj in input if 'type' in obj and str(obj['type']).lower() == "mfa_enroll" and 'status' in obj and str(obj['status']).lower() == "active"]
        mfa_info = {
            "isMFAEnforcedForUsers": True if mfa_enrolled is not None and len(mfa_enrolled) > 0 else False
        }
        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}
        