def transform(input):
    """
    Ensures a valid response is returned with a list of skus that are purchased. If list is non-empty, return true, otherwise return false.

    Parameters:
        input (dict): The JSON data containing expel API response

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

        # Check for subscription, license, or SKU indicators
        license_purchased = False
        license_details = {}

        # Check common license fields
        if 'subscription' in input and input['subscription']:
            license_purchased = True
            license_details['subscription'] = input['subscription']
        elif 'sku' in input and input['sku']:
            license_purchased = True
            license_details['sku'] = input['sku']
        elif 'license' in input and input['license']:
            license_purchased = True
            license_details['license'] = input['license']
        elif 'licenses' in input and len(input.get('licenses', [])) > 0:
            license_purchased = True
            license_details['licenses'] = input['licenses']
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
