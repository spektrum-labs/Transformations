def transform(input):
    """
    Evaluates if a valid Avanan (Check Point) license/subscription is active.

    The Avanan API requires successful authentication to access any endpoint.
    If we receive a valid response (token or security events), the license is active.

    Parameters:
        input (dict): The JSON data from Avanan API authentication or security events endpoint.

    Returns:
        dict: A dictionary summarizing the license purchase information.
    """

    try:
        if 'response' in input:
            input = input['response']
        
        default_value = True if input is not None else False

        # Check for explicit license field or infer from data presence
        license_purchased = input.get('licensePurchased', default_value)
        
        # If token was generated successfully, platform is licensed
        if 'token' in input and input.get('token'):
            license_purchased = True
        
        # If security events or entities exist, platform is licensed
        if 'securityEvents' in input or 'entities' in input or 'responseData' in input:
            license_purchased = True
            
        # If we received any exceptions data, platform is licensed
        if 'exceptions' in input:
            license_purchased = True

        license_info = {
            "confirmedLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}

