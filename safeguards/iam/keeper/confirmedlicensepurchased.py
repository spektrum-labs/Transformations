def transform(input):
    """
    Validates that a valid Keeper enterprise license is active.

    Evaluates Commander whoami or enterprise info for license status.
    Commander: whoami

    Parameters:
        input (dict): The JSON data from Keeper Commander whoami or enterprise info response

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
        if 'data' in input:
            input = input['data']

        license_confirmed = True if 'schemas' in input else False

        # Check for enterprise license indicators
        if 'enterprise' in input:
            enterprise = input['enterprise']
            if isinstance(enterprise, dict):
                license_confirmed = bool(enterprise.get('name') or enterprise.get('id'))
            else:
                license_confirmed = bool(enterprise)

        # Check for license/subscription fields
        if 'license' in input:
            license_info = input['license']
            if isinstance(license_info, dict):
                license_confirmed = license_info.get('active', False) or license_info.get('valid', False)
            else:
                license_confirmed = bool(license_info)

        # Check for account type indicators
        if 'account_type' in input:
            account_type = str(input['account_type']).lower()
            license_confirmed = account_type in ['enterprise', 'business', 'msp']

        # Check for subscription status
        if 'subscription' in input:
            subscription = input['subscription']
            if isinstance(subscription, dict):
                license_confirmed = subscription.get('active', False) or subscription.get('status') == 'active'
            else:
                license_confirmed = bool(subscription)

        # Check for user count (indicates enterprise)
        if 'user_count' in input or 'users' in input:
            user_count = input.get('user_count', len(input.get('users', [])))
            if user_count > 0:
                license_confirmed = True

        return {criteria_key: license_confirmed}

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
