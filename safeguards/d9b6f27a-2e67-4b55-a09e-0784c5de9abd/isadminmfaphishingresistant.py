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

        # Initialize counters
        if 'response' in input:
            input = input['response']
            
        if 'authenticationMethodConfigurations' in input:
            mfa_enrolled = [{"id": obj['id'] if 'id' in obj else '', "state": obj['state'] if 'state' in obj else 'enabled', "includeTargets": obj['includeTargets'] if 'includeTargets' in obj else []} for obj in input['authenticationMethodConfigurations'] if 'state' in obj and str(obj['state']).lower() == "enabled"]
        else:
            mfa_enrolled = []

        # Filter to keep only auth types that are NOT FIDO or OTP
        otherAuthTypes = [auth_type for auth_type in mfa_enrolled if auth_type['id'].lower() not in ['fido2', 'microsoftauthenticator']]
        
        return { 
            "isAdminMFAPhishingResistant": False if len(otherAuthTypes) > 0 else True,
            "authTypes": otherAuthTypes
        }

    except Exception as e:
        return { "isAdminMFAPhishingResistant": False, "authTypes": [], "error": str(e) }
