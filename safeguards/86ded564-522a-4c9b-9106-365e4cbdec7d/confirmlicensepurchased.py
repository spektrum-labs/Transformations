def transform(input):
    """
    Evaluates if the license has been purchased for the given IDP

    Parameters:
        input (dict): The JSON data containing IDP information.

    Returns:
        dict: A dictionary summarizing the license purchase information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
        
        default_value = True if input is not None else False

        license_purchased = input.get('licensePurchased', default_value)
        license_info = {
            "confirmLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmLicensePurchased": False, "error": str(e)}
        