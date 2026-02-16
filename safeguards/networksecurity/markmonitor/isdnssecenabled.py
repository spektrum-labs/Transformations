def transform(input):
    """
    Checks if DNSSEC is enabled via Mark Monitor

    Parameters:
        input (dict): The JSON data containing Mark Monitor DNSSEC status API response

    Returns:
        dict: A dictionary with the isDNSSECEnabled evaluation result
    """

    criteria_key = "isDNSSECEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        dnssec_enabled = False
        dnssec_details = {}

        # Check DNSSEC status
        if 'dnssec' in input:
            dnssec = input['dnssec']
            if isinstance(dnssec, dict):
                status = dnssec.get('status', dnssec.get('enabled', False))
                if isinstance(status, str):
                    dnssec_enabled = status.lower() in ['active', 'enabled', 'signed']
                else:
                    dnssec_enabled = bool(status)
                dnssec_details['dnssec'] = dnssec
            elif isinstance(dnssec, bool):
                dnssec_enabled = dnssec

        # Check domains for DNSSEC status
        elif 'domains' in input:
            domains = input['domains']
            if isinstance(domains, list):
                dnssec_domains = [d for d in domains if d.get('dnssecEnabled', d.get('dnssec', False))]
                dnssec_details['totalDomains'] = len(domains)
                dnssec_details['dnssecEnabledDomains'] = len(dnssec_domains)
                dnssec_enabled = len(dnssec_domains) > 0

        # Direct status check
        elif 'status' in input:
            status = input['status']
            if isinstance(status, str):
                dnssec_enabled = status.lower() in ['active', 'enabled', 'signed']
            dnssec_details['status'] = status
        elif 'enabled' in input:
            dnssec_enabled = bool(input['enabled'])

        return {
            criteria_key: dnssec_enabled,
            **dnssec_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
