def transform(input):
    """
    Evaluates if the SSO is enabled

    Parameters:
        input (dict): The JSON data containing IDP information.

    Returns:
        dict: A dictionary summarizing the SSO information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
        
        default_value = True if input is not None else False

        is_sso_enabled = input.get('isSSOEnabled', default_value)
        is_sso_enabled_mdr = input.get('isSSOEnabledMDR', default_value)
        sso_info = {
            "isSSOEnabled": is_sso_enabled,
            "isSSOEnabledMDR": is_sso_enabled_mdr
        }
        return sso_info
    except Exception as e:
        return {"isSSOEnabled": False,"isSSOEnabledMDR": False, "error": str(e)}
        