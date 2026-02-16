def transform(input):
    """
    Ensures a valid response is returned, returns the licensePurchased field value from the response.

    Parameters:
        input (dict): The JSON data containing Axonius health check API response

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

        # Axonius about endpoint returns instance info
        if 'Build Date' in input or 'build_date' in input:
            license_purchased = True
            license_details['buildDate'] = input.get('Build Date', input.get('build_date', ''))
        elif 'Version' in input or 'version' in input:
            license_purchased = True
            license_details['version'] = input.get('Version', input.get('version', ''))
        elif 'subscription' in input and input['subscription']:
            license_purchased = True
            license_details['subscription'] = input['subscription']
        elif 'license' in input and input['license']:
            license_purchased = True
            license_details['license'] = input['license']
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
