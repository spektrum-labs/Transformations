def transform(input):
    """
    Checks if logging/diagnostics are enabled for Azure Firewall

    Parameters:
        input (dict): The JSON data containing Azure diagnostic settings API response

    Returns:
        dict: A dictionary with the isFirewallLoggingEnabled evaluation result
    """

    criteria_key = "isFirewallLoggingEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        logging_enabled = False
        logging_details = {}

        # Azure diagnostic settings response
        value = input.get('value', [])
        if isinstance(value, list) and len(value) > 0:
            for setting in value:
                props = setting.get('properties', {})
                logs = props.get('logs', [])
                enabled_logs = [l for l in logs if l.get('enabled', False)]
                if len(enabled_logs) > 0:
                    logging_enabled = True
                    logging_details['diagnosticSettingName'] = setting.get('name', '')
                    logging_details['enabledLogCategories'] = len(enabled_logs)
                    break
        elif 'properties' in input:
            props = input['properties']
            logs = props.get('logs', [])
            enabled_logs = [l for l in logs if l.get('enabled', False)]
            logging_enabled = len(enabled_logs) > 0
            logging_details['enabledLogCategories'] = len(enabled_logs)

        return {
            criteria_key: logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
