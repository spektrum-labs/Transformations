def transform(input):
    """
    Evaluates if the license has been purchased for the given Firewall

    Parameters:
        input (dict): The JSON data containing Firewall information.

    Returns:
        dict: A dictionary summarizing the license purchase information.
    """

    try:
        is_license_purchased = False

        if 'items' in input:
            items = input['items']
            is_license_purchased = True if len(items) > 0 else False

        return { "confirmedLicensePurchased": is_license_purchased }
    except Exception as e:
        return { "confirmedLicensePurchased": False, "error": str(e) }
        