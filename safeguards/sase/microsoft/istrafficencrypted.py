def transform(input):
    """
    Checks if traffic encryption is configured in Microsoft Global Secure Access

    Parameters:
        input (dict): The JSON data containing Microsoft cross-tenant access settings API response

    Returns:
        dict: A dictionary with the isTrafficEncrypted evaluation result
    """

    criteria_key = "isTrafficEncrypted"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        traffic_encrypted = False
        encryption_details = {}

        # Microsoft cross-tenant access / network access settings
        # Check forwarding profiles for encryption settings
        value = input.get('value', [])
        if isinstance(value, list):
            for profile in value:
                traffic_type = profile.get('trafficForwardingType', '')
                state = profile.get('state', '')
                if state.lower() == 'enabled':
                    traffic_encrypted = True
                    encryption_details['enabledTrafficType'] = traffic_type

            encryption_details['totalProfiles'] = len(value)

        # Cross-tenant access settings indicate encrypted B2B connections
        elif 'b2bCollaborationInbound' in input or 'b2bCollaborationOutbound' in input:
            inbound = input.get('b2bCollaborationInbound', {})
            outbound = input.get('b2bCollaborationOutbound', {})
            traffic_encrypted = True
            encryption_details['b2bInbound'] = bool(inbound)
            encryption_details['b2bOutbound'] = bool(outbound)

        # Direct state check
        elif 'state' in input:
            traffic_encrypted = input['state'].lower() == 'enabled'
            encryption_details['state'] = input['state']

        return {
            criteria_key: traffic_encrypted,
            **encryption_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
