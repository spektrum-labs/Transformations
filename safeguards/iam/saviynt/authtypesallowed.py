def transform(input):
    """
    Return allowed MFA authentication types

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the authTypesAllowed evaluation result and list of auth types
    """

    criteria_key = "authTypesAllowed"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        auth_types = []

        # Check for entitlements/factors array (Saviynt getMFAFactors response)
        if 'entitlements' in input:
            entitlements = input['entitlements']
            if isinstance(entitlements, list):
                for ent in entitlements:
                    factor_type = ent.get('entitlement_value', ent.get('entitlementvalue', ent.get('factorType', '')))
                    if factor_type:
                        # Normalize factor types
                        factor_lower = str(factor_type).lower()
                        if 'totp' in factor_lower or 'token:software:totp' in factor_lower:
                            auth_types.append('OTP')
                        elif 'fido' in factor_lower or 'webauthn' in factor_lower:
                            auth_types.append('FIDO')
                        elif 'push' in factor_lower:
                            auth_types.append('PUSH')
                        elif 'sms' not in factor_lower:  # Exclude SMS
                            auth_types.append(factor_type)
        elif 'factors' in input:
            factors = input['factors']
            if isinstance(factors, list):
                for factor in factors:
                    factor_type = factor.get('factorType', factor.get('type', ''))
                    if factor_type and 'sms' not in str(factor_type).lower():
                        auth_types.append(factor_type)
        elif 'allowedTypes' in input:
            allowed = input['allowedTypes']
            if isinstance(allowed, list):
                auth_types = [t for t in allowed if 'sms' not in str(t).lower()]

        # Remove duplicates while preserving order
        auth_types = list(dict.fromkeys(auth_types))

        # Filter to check if only strong auth types are allowed (FIDO, OTP)
        weak_auth_types = [t for t in auth_types if str(t).lower() not in ['fido', 'otp', 'push', 'webauthn']]
        strong_auth_only = len(weak_auth_types) == 0 and len(auth_types) > 0

        return {
            criteria_key: strong_auth_only,
            "authTypes": auth_types,
            "weakAuthTypesFound": weak_auth_types
        }

    except Exception as e:
        return {
            criteria_key: False,
            "authTypes": [],
            "error": str(e)
        }
