def transform(input):
    """
    Checks if anti-phishing protection is enabled in Abnormal Security

    Parameters:
        input (dict): The JSON data containing Abnormal Security threats API response

    Returns:
        dict: A dictionary with the isAntiPhishingEnabled evaluation result
    """

    criteria_key = "isAntiPhishingEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        anti_phishing_enabled = False
        phishing_details = {}

        # Abnormal Security threats response
        threats = input.get('threats', input.get('results', []))
        if isinstance(threats, list):
            phishing_details['totalThreats'] = len(threats)
            # If the endpoint responds, anti-phishing is active
            anti_phishing_enabled = True

            phishing_threats = [t for t in threats if 'phishing' in t.get('threatType', '').lower() or 'phish' in t.get('attackType', '').lower()]
            phishing_details['phishingThreatsDetected'] = len(phishing_threats)
        elif 'total_count' in input or 'pageNumber' in input:
            # Paginated response indicates service is active
            anti_phishing_enabled = True
            phishing_details['totalCount'] = input.get('total_count', 0)
        elif 'settings' in input:
            settings = input['settings']
            anti_phishing_enabled = settings.get('phishingProtection', {}).get('enabled', False)
            phishing_details['settings'] = settings

        return {
            criteria_key: anti_phishing_enabled,
            **phishing_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
