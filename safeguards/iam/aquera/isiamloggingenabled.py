def transform(input):
    """
    Checks if IAM audit logging is enabled in Aquera

    Parameters:
        input (dict): The JSON data containing Aquera audit logs API response

    Returns:
        dict: A dictionary with the isIAMLoggingEnabled evaluation result
    """

    criteria_key = "isIAMLoggingEnabled"

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

        # Check audit logs
        logs = input.get('auditLogs', input.get('logs', input.get('data', input.get('value', []))))
        if isinstance(logs, list):
            logging_details['logCount'] = len(logs)
            logging_enabled = len(logs) > 0
        elif isinstance(logs, dict):
            items = logs.get('items', logs.get('records', []))
            if isinstance(items, list):
                logging_details['logCount'] = len(items)
                logging_enabled = len(items) > 0

        # Check logging configuration
        if 'loggingConfig' in input or 'auditConfig' in input:
            config = input.get('loggingConfig', input.get('auditConfig', {}))
            if isinstance(config, dict):
                logging_enabled = config.get('enabled', logging_enabled)
                logging_details['config'] = config

        # Check for total count in paginated response
        if 'totalCount' in input or 'total' in input:
            total = input.get('totalCount', input.get('total', 0))
            logging_details['totalLogs'] = total
            logging_enabled = total > 0

        return {
            criteria_key: logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
