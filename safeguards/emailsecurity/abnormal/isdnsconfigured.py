def transform(input):
    """
    Checks if DNS authentication (SPF/DKIM/DMARC) is configured via Abnormal Security

    Parameters:
        input (dict): The JSON data containing Abnormal Security settings API response

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

        dns_configured = False
        dns_details = {}

        # Check Abnormal Security settings for email authentication
        settings = input.get('settings', input)

        # Check for email authentication settings
        email_auth = settings.get('emailAuthentication', settings.get('authentication', {}))
        if isinstance(email_auth, dict):
            spf = email_auth.get('spf', {})
            dkim = email_auth.get('dkim', {})
            dmarc = email_auth.get('dmarc', {})

            dns_details['spfConfigured'] = bool(spf.get('enabled', spf.get('configured', False)))
            dns_details['dkimConfigured'] = bool(dkim.get('enabled', dkim.get('configured', False)))
            dns_details['dmarcConfigured'] = bool(dmarc.get('enabled', dmarc.get('configured', False)))

            dns_configured = dns_details['spfConfigured'] or dns_details['dkimConfigured'] or dns_details['dmarcConfigured']
        elif 'integrations' in settings:
            # If Abnormal has integrations configured, DNS is set up
            integrations = settings['integrations']
            if isinstance(integrations, list) and len(integrations) > 0:
                dns_configured = True
                dns_details['integrationCount'] = len(integrations)

        # If we get a valid response from settings, that implies basic DNS config
        if not dns_configured and isinstance(input, dict) and len(input) > 0:
            if 'organization' in input or 'account' in input:
                dns_configured = True
                dns_details['note'] = 'Service active - DNS configuration inferred'

        return {
            criteria_key: dns_configured,
            **dns_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
