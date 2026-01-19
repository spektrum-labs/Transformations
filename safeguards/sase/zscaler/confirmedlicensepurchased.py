def transform(input):
    """
    Evaluates if a valid Zscaler ZIA subscription is active.

    The Zscaler ZIA API requires successful authentication to access any endpoint.
    If we receive a valid status response, the subscription is active.

    Parameters:
        input (dict): The JSON data from Zscaler ZIA status endpoint.

    Returns:
        dict: A dictionary summarizing the license purchase information.
    """

    try:
        if 'response' in input:
            input = input['response']

        default_value = True if input is not None else False

        # Check for explicit license field or infer from data presence
        license_purchased = input.get('licensePurchased', default_value)

        # Check for status response indicating active subscription
        status = input.get('status', input.get('responseData', {}))
        if isinstance(status, dict) and status:
            license_purchased = True

        # Check for cloud name or organization info (indicates active subscription)
        if input.get('cloudName') or input.get('orgName') or input.get('organization'):
            license_purchased = True

        # If we received any valid data, the platform is licensed
        if 'apiResponse' in input and input.get('apiResponse'):
            license_purchased = True

        license_info = {
            "confirmedLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
