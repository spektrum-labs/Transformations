def transform(input):
    """
    Checks if VPN is enabled by verifying remote access users and policies in Cato

    Parameters:
        input (dict): The JSON data containing Cato VPN users API response

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

        # Cato GraphQL response
        data = input.get('data', input)

        # Check for VPN users
        vpn_users = data.get('vpnUsers', data.get('remoteAccessUsers', {}))
        if isinstance(vpn_users, list):
            vpn_details['totalVPNUsers'] = len(vpn_users)
            connected = [u for u in vpn_users if u.get('connectivityStatus', '') == 'connected']
            vpn_details['connectedUsers'] = len(connected)
            vpn_enabled = len(vpn_users) > 0
        elif isinstance(vpn_users, dict):
            items = vpn_users.get('items', vpn_users.get('users', []))
            if isinstance(items, list):
                vpn_details['totalVPNUsers'] = len(items)
                vpn_enabled = len(items) > 0

        # Check remote access policy
        policy = data.get('policy', {})
        remote_access = policy.get('remoteAccess', {})
        if isinstance(remote_access, dict):
            ra_policy = remote_access.get('policy', {})
            enabled = ra_policy.get('enabled', False)
            vpn_details['remoteAccessEnabled'] = enabled
            if enabled:
                vpn_enabled = True

        return {
            criteria_key: vpn_enabled,
            **vpn_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
