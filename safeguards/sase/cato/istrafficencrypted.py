def transform(input):
    """
    Checks if traffic encryption is enabled in Cato Networks

    Parameters:
        input (dict): The JSON data containing Cato network policies API response

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

        # Cato GraphQL response
        data = input.get('data', input)
        policy = data.get('policy', data)

        # Check TLS inspection policy
        tls_inspection = policy.get('tlsInspection', {})
        if isinstance(tls_inspection, dict):
            tls_policy = tls_inspection.get('policy', {})
            tls_enabled = tls_policy.get('enabled', False)
            encryption_details['tlsInspectionEnabled'] = tls_enabled
            if tls_enabled:
                traffic_encrypted = True

        # Check WAN encryption
        wan_network = policy.get('wanNetwork', {})
        if isinstance(wan_network, dict):
            wan_policy = wan_network.get('policy', {})
            wan_enabled = wan_policy.get('enabled', False)
            encryption_details['wanEncryptionEnabled'] = wan_enabled
            if wan_enabled:
                traffic_encrypted = True

        # Cato SASE inherently encrypts traffic via tunnels
        account = data.get('accountSnapshot', data.get('account', {}))
        if isinstance(account, dict):
            sites = account.get('sites', [])
            if isinstance(sites, list) and len(sites) > 0:
                traffic_encrypted = True
                encryption_details['connectedSites'] = len(sites)

        return {
            criteria_key: traffic_encrypted,
            **encryption_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
