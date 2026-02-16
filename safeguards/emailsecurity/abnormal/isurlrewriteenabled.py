def transform(input):
    """
    Checks if URL rewrite/safe links protection is enabled in Abnormal Security

    Parameters:
        input (dict): The JSON data containing Abnormal Security settings API response

    Returns:
        dict: A dictionary with the isURLRewriteEnabled evaluation result
    """

    criteria_key = "isURLRewriteEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        url_rewrite_enabled = False
        url_details = {}

        # Check settings for URL protection
        settings = input.get('settings', input)

        # Check URL protection settings
        url_protection = settings.get('urlProtection', settings.get('linkProtection', {}))
        if isinstance(url_protection, dict):
            url_rewrite_enabled = url_protection.get('enabled', False)
            url_details['urlProtection'] = url_protection

        # Check for remediation actions that include URL rewriting
        remediation = settings.get('remediationActions', settings.get('remediation', {}))
        if isinstance(remediation, dict):
            actions = remediation.get('actions', [])
            if isinstance(actions, list):
                url_actions = [a for a in actions if 'url' in str(a).lower() or 'link' in str(a).lower()]
                if len(url_actions) > 0:
                    url_rewrite_enabled = True
                    url_details['urlRemediationActions'] = len(url_actions)

        # Abnormal's core product includes URL analysis
        if not url_rewrite_enabled:
            threats = input.get('threats', input.get('results', []))
            if isinstance(threats, list) and len(threats) > 0:
                url_threats = [t for t in threats if t.get('attackVector', '').lower() == 'url' or 'url' in t.get('threatType', '').lower()]
                if len(url_threats) > 0:
                    url_rewrite_enabled = True
                    url_details['urlThreatsDetected'] = len(url_threats)

        return {
            criteria_key: url_rewrite_enabled,
            **url_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
