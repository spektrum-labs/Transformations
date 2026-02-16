def transform(input):
    """
    Ensures a valid response is returned, returns the licensePurchased field value from the response.

    Parameters:
        input (dict): The JSON data containing Microsoft Graph API response

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

        # Microsoft Graph subscribedSkus response
        value = input.get('value', [])
        if isinstance(value, list) and len(value) > 0:
            enabled_skus = [s for s in value if s.get('capabilityStatus') == 'Enabled']
            license_purchased = len(enabled_skus) > 0
            license_details['totalSkus'] = len(value)
            license_details['enabledSkus'] = len(enabled_skus)
        elif 'subscription' in input and input['subscription']:
            license_purchased = True
            license_details['subscription'] = input['subscription']
        elif 'sku' in input and input['sku']:
            license_purchased = True
            license_details['sku'] = input['sku']
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
