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
            
        mfa_enrolled = [obj for obj in input if hasattr(obj, 'type') and getattr(obj, 'type') == "MFA_ENROLL"]
        mfa_info = {
            "isMFAEnforcedForUsers": True if mfa_enrolled is not None and len(mfa_enrolled) > 0 else False
        }
        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}
        