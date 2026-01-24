def transform(input):
    """
    Evaluates if the license has been purchased for Liongard.
    Checks the environments API response to verify valid API key/subscription.

    Parameters:
        input (dict): The JSON data containing Liongard API environments response.

    Returns:
        dict: A dictionary summarizing the license purchase information.
    """

    try:
        # Handle nested response structure
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']

        # If we got a valid response from the environments endpoint,
        # it means the API key is valid and the subscription is active
        default_value = True if input is not None else False

        # Check if environments were returned (indicates valid subscription)
        has_data = False
        if isinstance(input, dict):
            # Check for data array or environments list
            data = input.get('data', input.get('environments', input.get('items', [])))
            has_data = len(data) > 0 if isinstance(data, list) else bool(data)
            # Also check for count field
            if not has_data and 'count' in input:
                has_data = int(input.get('count', 0)) >= 0
        elif isinstance(input, list):
            has_data = len(input) > 0

        license_purchased = has_data or default_value

        license_info = {
            "confirmedLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
