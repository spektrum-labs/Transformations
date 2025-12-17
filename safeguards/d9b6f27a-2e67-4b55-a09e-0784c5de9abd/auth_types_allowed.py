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
        # Check if "temporaryAccess" is in the list
        has_temporary_access = any(auth_type['id'].lower() == 'temporaryaccesspass' for auth_type in mfa_enrolled)
        # Check if "fido2" or "microsoftauthenticator" is in the list
        has_fido2 = any(auth_type['id'].lower() == 'fido2' for auth_type in mfa_enrolled)
        has_ms_auth = any(auth_type['id'].lower() == 'microsoftauthenticator' for auth_type in mfa_enrolled)

        #Check if all the auth types are present
        if len(otherAuthTypes) > 0:
            if has_temporary_access and (has_fido2 or has_ms_auth):
                authTypesAllowed = True
            else:
                authTypesAllowed = False
        else:
            authTypesAllowed = True
        return { 
            "authTypesAllowed": authTypesAllowed,
            "authTypes": otherAuthTypes
        }

    except Exception as e:
        return { "authTypesAllowed": False, "authTypes": [], "error": str(e) }
