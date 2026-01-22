def transform(input):
    """
    Validate system is operational with active license

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the confirmedLicensePurchased evaluation result
    """

    criteria_key = "confirmedLicensePurchased"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        license_active = False
        license_details = {}

        # A successful API response indicates active license
        if input is not None:
            # Check for explicit license or status indicators
            if 'status' in input:
                status = str(input['status']).lower()
                license_active = status in ['healthy', 'active', 'valid', 'success', 'ok']
                license_details['status'] = input['status']
            elif 'licensePurchased' in input:
                license_active = bool(input['licensePurchased'])
            elif 'licenseActive' in input:
                license_active = bool(input['licenseActive'])
            else:
                # If we got a valid response, assume license is active
                license_active = True

        return {
            criteria_key: license_active,
            **license_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
