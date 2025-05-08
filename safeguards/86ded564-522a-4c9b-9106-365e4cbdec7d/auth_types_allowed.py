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
                        authTypes.append('TOTP')
                    else:
                        authTypes.append(item.get('factorType'))

        return { "authTypesAllowed": authTypes }

    except Exception as e:
        return { "authTypesAllowed": authTypes, "error": str(e) }
