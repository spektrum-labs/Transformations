def transform(input):
    """
    Ensures a valid response is returned, returns the licensePurchased field value from the response.

    Parameters:
        input (dict): The JSON data containing Fortinet system status API response

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

        license_purchased = False
        license_details = {}

        # Fortinet system status returns version/serial info
        results = input.get('results', input)
        if isinstance(results, dict):
            serial = results.get('serial', '')
            version = results.get('version', '')
            if serial or version:
                license_purchased = True
                license_details['serial'] = serial
                license_details['version'] = version
        elif 'serial' in input and input['serial']:
            license_purchased = True
            license_details['serial'] = input['serial']
        elif 'version' in input and input['version']:
            license_purchased = True
            license_details['version'] = input['version']
        elif 'subscription' in input and input['subscription']:
            license_purchased = True
            license_details['subscription'] = input['subscription']
        elif 'active' in input or 'enabled' in input:
            license_purchased = bool(input.get('active', input.get('enabled', False)))
            license_details['status'] = 'active' if license_purchased else 'inactive'

        return {
            criteria_key: license_purchased,
            **license_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
