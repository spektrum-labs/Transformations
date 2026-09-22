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
        
        # `input is not None` asked whether a RESPONSE ARRIVED, not what it said, so any
        # 2xx body -- including one describing the control as OFF -- satisfied this
        # criterion and no input could make it false. Resolved from the payload now.
        default_value = _affirmative_signal(input)

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


def _affirmative_signal(data):
    """True only when the payload POSITIVELY evidences the control.

    Replaces `data is not None`, which asked whether a response arrived rather than what
    it said -- so any 2xx body, including one describing the control as OFF, satisfied the
    criterion and no input could ever make it false. Measured 2026-09-21.

    Deliberately conservative, in this order:
      * an unreadable, empty or error body           -> False
      * an explicit OFF among the recognised keys    -> False   (beats any other signal)
      * an explicit ON among the recognised keys     -> True
      * a non-empty population of records/settings   -> True
      * anything unrecognised                        -> False  (never True by default)
    """
    if not isinstance(data, dict) or not data:
        return False
    for key in ("error", "errors", "errorMessage", "errorType", "fault", "PSError"):
        if data.get(key):
            return False
    on_keys = ("enabled", "isEnabled", "active", "isActive", "configured", "isConfigured",
               "enforced", "isEnforced", "loggingEnabled", "status", "state", "licensed",
               "licensePurchased", "subscribed", "subscription")
    present = [data[k] for k in on_keys if k in data]
    off_words = ("false", "disabled", "off", "inactive", "none", "expired", "cancelled")
    on_words = ("true", "enabled", "on", "active", "success", "ok", "valid", "licensed")
    for value in present:
        if value is False:
            return False
        if isinstance(value, str) and value.strip().lower() in off_words:
            return False
    for value in present:
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in on_words:
            return True
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return True
    for key in ("items", "data", "records", "results", "logs", "events", "policies",
                "settings", "configurations", "devices", "agents", "users", "licenses"):
        value = data.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
    return False
