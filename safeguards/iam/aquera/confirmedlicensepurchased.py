def transform(input):
    """
    Ensures a valid response is returned, returns the licensePurchased field value from the response.

    Parameters:
        input (dict): The JSON data containing Aquera API response

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

        # Aquera health check response
        if 'tenantId' in input or 'tenant_id' in input:
            license_purchased = True
            license_details['tenantId'] = input.get('tenantId', input.get('tenant_id', ''))
        elif 'subscription' in input and input['subscription']:
            license_purchased = True
            license_details['subscription'] = input['subscription']
        elif 'license' in input and input['license']:
            license_purchased = True
            license_details['license'] = input['license']
        elif 'status' in input and input['status'].lower() in ['active', 'ok', 'healthy']:
            license_purchased = True
            license_details['status'] = input['status']
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
