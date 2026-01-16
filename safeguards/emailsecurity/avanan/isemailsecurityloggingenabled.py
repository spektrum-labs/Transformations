def transform(input):
    """
    Evaluates if email security logging is enabled in Avanan.
    
    Checks for presence of audit logs and security event logs.

    Parameters:
        input (dict): The JSON data from Avanan audit logs endpoint.

    Returns:
        dict: A dictionary summarizing the email security logging information.
    """

    try:
        if 'response' in input:
            input = input['response']
        
        default_value = True if input is not None else False

        # Check for explicit logging status
        email_security_logging_enabled = input.get('isEmailSecurityLoggingEnabled', False)
        
        # If audit logs exist, logging is enabled
        audit_logs = input.get('auditLogs', input.get('responseData', []))
        security_events = input.get('securityEvents', [])
        
        if isinstance(audit_logs, list) and len(audit_logs) > 0:
            email_security_logging_enabled = True
        if isinstance(security_events, list) and len(security_events) > 0:
            email_security_logging_enabled = True
        
        # If we got valid data, assume logging is enabled
        if not email_security_logging_enabled:
            email_security_logging_enabled = default_value

        email_security_logging_info = {
            "isEmailSecurityLoggingEnabled": email_security_logging_enabled,
            "isEmailLoggingEnabled": email_security_logging_enabled,
            "auditLogsCount": len(audit_logs) if isinstance(audit_logs, list) else 0,
            "securityEventsCount": len(security_events) if isinstance(security_events, list) else 0
        }
        return email_security_logging_info
    except Exception as e:
        return {"isEmailSecurityLoggingEnabled": False, "isEmailLoggingEnabled": False, "error": str(e)}

