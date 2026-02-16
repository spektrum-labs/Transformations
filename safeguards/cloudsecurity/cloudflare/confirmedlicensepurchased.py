def transform(input):
    """
    Ensures a valid response is returned, returns the licensePurchased field value from the response.

    Parameters:
        input (dict): The JSON data containing Cloudflare API response

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

        # Cloudflare zone details endpoint
        if isinstance(input, dict):
            plan = input.get('plan', {})
            if plan and isinstance(plan, dict):
                plan_name = plan.get('name', '')
                license_purchased = bool(plan_name)
                license_details['plan'] = plan_name
            elif 'status' in input and input['status'] == 'active':
                license_purchased = True
                license_details['status'] = 'active'
            elif 'subscription' in input and input['subscription']:
                license_purchased = True
                license_details['subscription'] = input['subscription']
            elif 'success' in input:
                license_purchased = input.get('success', False)

        return {
            criteria_key: license_purchased,
            **license_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
