def transform(input):
    """
    Checks if SASE is enabled via Microsoft Global Secure Access

    Parameters:
        input (dict): The JSON data containing Microsoft network access status API response

    Returns:
        dict: A dictionary with the isSASEEnabled evaluation result
    """

    criteria_key = "isSASEEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        sase_enabled = False
        sase_details = {}

        # Microsoft Global Secure Access status
        # Check for forwarding profiles
        value = input.get('value', [])
        if isinstance(value, list) and len(value) > 0:
            enabled_profiles = []
            for profile in value:
                state = profile.get('state', '')
                name = profile.get('name', profile.get('displayName', ''))
                traffic_type = profile.get('trafficForwardingType', '')

                if state.lower() == 'enabled':
                    enabled_profiles.append({
                        'name': name,
                        'trafficType': traffic_type
                    })

            sase_details['totalProfiles'] = len(value)
            sase_details['enabledProfiles'] = len(enabled_profiles)
            sase_enabled = len(enabled_profiles) > 0

        # Direct status check
        elif 'state' in input:
            sase_enabled = input['state'].lower() == 'enabled'
            sase_details['state'] = input['state']
        elif 'status' in input:
            sase_enabled = input['status'].lower() in ['enabled', 'active']
            sase_details['status'] = input['status']

        return {
            criteria_key: sase_enabled,
            **sase_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
