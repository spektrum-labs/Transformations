def transform(input):
    """
    Checks if VPN is enabled via Microsoft Global Secure Access

    Parameters:
        input (dict): The JSON data containing Microsoft SASE network access API response

    Returns:
        dict: A dictionary with the isVPNEnabled evaluation result
    """

    criteria_key = "isVPNEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        vpn_enabled = False
        vpn_details = {}

        # Microsoft Global Secure Access response
        # Check forwarding profiles for private access (VPN replacement)
        value = input.get('value', [])
        if isinstance(value, list):
            for profile in value:
                name = profile.get('name', profile.get('displayName', ''))
                state = profile.get('state', '')
                traffic_type = profile.get('trafficForwardingType', '')

                if traffic_type == 'private' or 'private' in name.lower():
                    vpn_details['privateAccessProfile'] = name
                    vpn_details['privateAccessState'] = state
                    if state.lower() == 'enabled':
                        vpn_enabled = True

            vpn_details['totalProfiles'] = len(value)
        elif 'state' in input:
            vpn_enabled = input['state'].lower() == 'enabled'
            vpn_details['state'] = input['state']

        return {
            criteria_key: vpn_enabled,
            **vpn_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
