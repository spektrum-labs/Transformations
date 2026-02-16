def transform(input):
    """
    Checks if email logging/audit trail is enabled in Abnormal Security

    Parameters:
        input (dict): The JSON data containing Abnormal Security audit logs API response

    Returns:
        dict: A dictionary with the isEmailLoggingEnabled evaluation result
    """

    criteria_key = "isEmailLoggingEnabled"

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

        # Check audit logs response
        audit_logs = input.get('auditLogs', input.get('results', input.get('logs', [])))
        if isinstance(audit_logs, list):
            logging_details['logCount'] = len(audit_logs)
            logging_enabled = len(audit_logs) > 0
        elif 'total_count' in input:
            logging_details['totalCount'] = input['total_count']
            logging_enabled = input['total_count'] > 0
        elif 'pageNumber' in input:
            # Paginated response means logging is active
            logging_enabled = True

        # Check settings for logging configuration
        settings = input.get('settings', {})
        if isinstance(settings, dict):
            audit = settings.get('auditLogging', settings.get('logging', {}))
            if isinstance(audit, dict):
                logging_enabled = audit.get('enabled', logging_enabled)
                logging_details['auditLogging'] = audit

        return {
            criteria_key: logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
