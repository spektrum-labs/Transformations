def transform(input):
    """
    Returns a list of Authenticator Types that are active.
    """
    authTypes = []
    try:
        
        if isinstance(input, list):
            data = input
        elif isinstance(input, dict):
            data = input.get('response', input)

        for item in data:
            if item.get('status').lower() == 'active':
                if item.get('factorType').lower() != 'sms':
                    if item.get('factorType').lower() == 'token:software:totp':
                        authTypes.append('OTP')
                    else:
                        authTypes.append(item.get('factorType'))

        # Filter to keep only auth types that are NOT FIDO or OTP
        otherAuthTypes = [auth_type for auth_type in authTypes if auth_type.lower() not in ['fido', 'otp']]
        
        return { 
            "authTypesAllowed": False if len(otherAuthTypes) > 0 else True,
            "authTypes": authTypes
        }

    except Exception as e:
        return { "authTypesAllowed": False, "authTypes": [], "error": str(e) }
