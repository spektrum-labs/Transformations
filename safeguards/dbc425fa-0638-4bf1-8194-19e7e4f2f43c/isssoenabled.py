def transform(input):
    """
    Evaluates if SSO is enabled for the given Mail Provider

    Parameters:
        input (dict): The JSON data containing Mail Provider information.

    Returns:
        dict: A dictionary summarizing the SSO information.
    """

    try:
        # Initialize variables
        isSSOEnabled = False

        if 'result' in input:
            input = input['result']

        if 'idpInfo' in input:
            input = input['idpInfo']
            
        sso_enabled = [obj for obj in input if '@name' in obj and str(obj['@name']).lower() == "enablesso"]
        if len(sso_enabled) > 0 and '@value' in sso_enabled[0]:            
            isSSOEnabled = bool(str(sso_enabled[0]['@value']))

        sso_info = {
            "isSSOEnabled": isSSOEnabled
        }
        return sso_info
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}
        