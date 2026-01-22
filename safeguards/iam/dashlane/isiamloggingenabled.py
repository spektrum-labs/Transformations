def transform(input):
    """
    Validate that logs are captured and monitored

    Parameters:
        input (dict): The JSON data containing dashlane API response

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

        # Check logging status
        logging_enabled = False
        logging_details = {}

        # Check common logging fields
        if 'loggingEnabled' in input or 'auditEnabled' in input:
            logging_enabled = bool(input.get('loggingEnabled', input.get('auditEnabled', False)))
        elif 'enabled' in input:
            logging_enabled = bool(input['enabled'])
        elif 'state' in input or 'status' in input:
            state = str(input.get('state', input.get('status', ''))).lower()
            logging_enabled = state in ['enabled', 'active', 'on']
            logging_details['state'] = state
        elif 'logs' in input:
            logs = input['logs'] if isinstance(input['logs'], list) else []
            logging_enabled = len(logs) > 0
            logging_details['logCount'] = len(logs)
        elif 'auditLog' in input:
            logging_enabled = bool(input['auditLog'])
            logging_details['auditLog'] = input['auditLog']

        return {
            criteria_key: logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
