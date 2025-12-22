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

        # Find the temporaryaccesspass auth_type object
        temp_access_obj = next((auth_type for auth_type in mfa_enrolled if auth_type['id'].lower() == 'temporaryaccesspass'), None)
        # Check if temporaryaccesspass has a maximumLifetimeInMinutes > 0
        has_temporary_access = False
        temp_access_timeout = False
        if temp_access_obj is not None:
            has_temporary_access = True
            max_lifetime = temp_access_obj.get('maximumLifetimeInMinutes')
            try:
                if max_lifetime is not None and int(max_lifetime) > 0:
                    temp_access_timeout = True
            except Exception:
                pass  # Ignore if conversion fails, treat as not present/invalid

        # Check if "fido2" or "microsoftauthenticator" is in the list
        has_fido2 = any(auth_type['id'].lower() == 'fido2' for auth_type in mfa_enrolled)
        has_ms_auth = any(auth_type['id'].lower() == 'microsoftauthenticator' for auth_type in mfa_enrolled)

        #Check if all the auth types are present
        if len(otherAuthTypes) > 0:
            #Check if the only Auth Type is temporary access & it is configured for a max lifetime > 0 & FIDO2 or Microsoft Authenticator is present
            if len(otherAuthTypes) == 1 and has_temporary_access and temp_access_timeout and (has_fido2 or has_ms_auth):
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
