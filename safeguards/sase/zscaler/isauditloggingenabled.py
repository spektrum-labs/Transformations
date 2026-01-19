def transform(input):
    """
    Evaluates if admin audit logging is enabled in Zscaler ZIA.

    Checks for the presence of audit logs and logging configuration.

    Parameters:
        input (dict): The JSON data from Zscaler ZIA audit logs endpoint.

    Returns:
        dict: A dictionary summarizing the audit logging status.
    """

    try:
        if 'response' in input:
            input = input['response']

        isAuditLoggingEnabled = False
        logs_count = 0

        # Get audit logs from response
        audit_logs = input.get('auditLogs', input.get('responseData', []))

        if isinstance(audit_logs, list):
            logs_count = len(audit_logs)

            # If we have any audit logs, logging is enabled
            if logs_count > 0:
                isAuditLoggingEnabled = True

        # Check for explicit logging status
        if input.get('auditLoggingEnabled', False):
            isAuditLoggingEnabled = True

        if input.get('loggingEnabled', False):
            isAuditLoggingEnabled = True

        # Check for logging configuration
        logging_config = input.get('loggingConfig', input.get('auditConfig', {}))
        if isinstance(logging_config, dict) and logging_config.get('enabled', False):
            isAuditLoggingEnabled = True

        # If we successfully retrieved audit log data, logging is enabled
        if 'apiResponse' in input and input.get('apiResponse'):
            isAuditLoggingEnabled = True

        audit_logging_info = {
            "isAuditLoggingEnabled": isAuditLoggingEnabled,
            "logsCount": logs_count
        }
        return audit_logging_info
    except Exception as e:
        return {"isAuditLoggingEnabled": False, "error": str(e)}
