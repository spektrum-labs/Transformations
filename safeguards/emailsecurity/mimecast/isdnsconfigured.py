def transform(input):
    """
    Ensure that DMARC, DKIM and SPF records are set up properly

    Parameters:
        input (dict): The JSON data containing mimecast API response

    Returns:
        dict: A dictionary with the isDNSConfigured evaluation result
    """

    criteria_key = "isDNSConfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check DNS/email authentication configuration
        dns_configured = False
        dns_details = {}

        # Check for DNS/email auth records
        if 'dmarc' in input or 'dkim' in input or 'spf' in input:
            dmarc = bool(input.get('dmarc'))
            dkim = bool(input.get('dkim'))
            spf = bool(input.get('spf'))
            dns_configured = dmarc and dkim and spf
            dns_details['dmarc'] = dmarc
            dns_details['dkim'] = dkim
            dns_details['spf'] = spf
        elif 'records' in input:
            records = input['records'] if isinstance(input['records'], list) else []
            dns_configured = len(records) >= 3  # Expect DMARC, DKIM, SPF
            dns_details['records'] = len(records)
        elif 'configured' in input or 'enabled' in input:
            dns_configured = bool(input.get('configured', input.get('enabled', False)))
        elif 'emailAuthentication' in input:
            dns_configured = bool(input['emailAuthentication'])

        return {
            criteria_key: dns_configured,
            **dns_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
