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
        mfa_enrolled = input.get("status", None)
        mfa_info = {
            "isMFAEnforcedForUsers": True if mfa_enrolled is not None and mfa_enrolled == "ACTIVE" else False
        }
        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}
        