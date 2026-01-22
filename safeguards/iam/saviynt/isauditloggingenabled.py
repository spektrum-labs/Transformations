def transform(input):
    """
    Check if audit logs exist and logging is active

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the isAuditLoggingEnabled evaluation result
    """

    criteria_key = "isAuditLoggingEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        audit_logging_enabled = False
        audit_details = {}

        # Check for runtimecontrols array (Saviynt audit logs)
        if 'runtimecontrols' in input:
            controls = input['runtimecontrols']
            if isinstance(controls, list):
                audit_logging_enabled = len(controls) > 0
                audit_details['auditLogCount'] = len(controls)
        elif 'auditLogs' in input:
            logs = input['auditLogs']
            if isinstance(logs, list):
                audit_logging_enabled = len(logs) > 0
                audit_details['auditLogCount'] = len(logs)
        elif 'loggingEnabled' in input:
            audit_logging_enabled = bool(input['loggingEnabled'])

        return {
            criteria_key: audit_logging_enabled,
            **audit_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
