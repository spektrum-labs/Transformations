def transform(input):
    """
    Ensures a valid response is returned, returns the licensePurchased field value from the response.

    Parameters:
        input (dict): The JSON data containing Cato Networks licensing API response

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

        # Cato GraphQL response: data.licensing.licensingInfo
        data = input.get('data', input)
        licensing = data.get('licensing', data)
        licensing_info = licensing.get('licensingInfo', licensing)

        if 'licenses' in licensing_info:
            licenses = licensing_info['licenses']
            if isinstance(licenses, list) and len(licenses) > 0:
                active = [l for l in licenses if l.get('status', '').lower() == 'active']
                license_purchased = len(active) > 0
                license_details['totalLicenses'] = len(licenses)
                license_details['activeLicenses'] = len(active)
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
