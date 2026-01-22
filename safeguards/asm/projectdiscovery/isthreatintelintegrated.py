def transform(input):
    """
    Validates that CVE and threat intelligence templates are active

    Parameters:
        input (dict): The JSON data containing projectdiscovery API response

    Returns:
        dict: A dictionary with the isThreatIntelIntegrated evaluation result
    """

    criteria_key = "isThreatIntelIntegrated"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check threat intel integration
        threat_intel_integrated = False
        intel_details = {}

        # Check for threat intelligence indicators
        if 'threatIntelEnabled' in input or 'intelIntegrated' in input:
            threat_intel_integrated = bool(input.get('threatIntelEnabled', input.get('intelIntegrated', False)))
        elif 'templates' in input:
            templates = input['templates'] if isinstance(input['templates'], list) else []
            # Check for CVE or threat intel templates
            threat_templates = [t for t in templates if 'cve' in str(t).lower() or 'threat' in str(t).lower()]
            threat_intel_integrated = len(threat_templates) > 0
            intel_details['threatTemplates'] = len(threat_templates)
            intel_details['totalTemplates'] = len(templates)
        elif 'feeds' in input:
            feeds = input['feeds'] if isinstance(input['feeds'], list) else []
            threat_intel_integrated = len(feeds) > 0
            intel_details['feeds'] = feeds
        elif 'integrations' in input:
            integrations = input['integrations'] if isinstance(input['integrations'], list) else []
            threat_intel_integrated = len(integrations) > 0
            intel_details['integrations'] = integrations

        return {
            criteria_key: threat_intel_integrated,
            **intel_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
