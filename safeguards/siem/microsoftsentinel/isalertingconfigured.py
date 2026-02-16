def transform(input):
    """
    Checks if alerting rules are configured in Microsoft Sentinel

    Parameters:
        input (dict): The JSON data containing Microsoft Sentinel alert rules API response

    Returns:
        dict: A dictionary with the isAlertingConfigured evaluation result
    """

    criteria_key = "isAlertingConfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        alerting_configured = False
        alerting_details = {}

        # Azure Sentinel alert rules response
        rules = input.get('value', [])
        if isinstance(rules, list):
            total = len(rules)
            alerting_details['totalRules'] = total

            enabled_rules = []
            for rule in rules:
                props = rule.get('properties', {})
                enabled = props.get('enabled', False)
                if enabled:
                    enabled_rules.append({
                        'name': rule.get('name', ''),
                        'kind': rule.get('kind', ''),
                        'severity': props.get('severity', '')
                    })

            alerting_details['enabledRules'] = len(enabled_rules)
            alerting_configured = len(enabled_rules) > 0

        return {
            criteria_key: alerting_configured,
            **alerting_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
