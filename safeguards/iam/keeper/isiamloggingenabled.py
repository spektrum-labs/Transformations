def transform(input):
    """
    Validates that audit logging is enabled and capturing events in Keeper.

    Parameters:
        input (dict): The JSON data from Keeper audit-log command response

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
        if 'data' in input:
            input = input['data']

        logging_enabled = False
        logging_details = {
            "eventCount": 0,
            "hasRecentEvents": False
        }

        # Check for audit logs array
        audit_logs = input.get('auditLogs', input.get('audit_logs', input.get('events', [])))
        if isinstance(audit_logs, list):
            logging_details["eventCount"] = len(audit_logs)
            # If we have audit logs, logging is enabled
            logging_enabled = len(audit_logs) > 0
            logging_details["hasRecentEvents"] = len(audit_logs) > 0

        # Check for logging configuration
        if 'logging' in input:
            logging_config = input['logging']
            if isinstance(logging_config, dict):
                logging_enabled = logging_config.get('enabled', False) or \
                                  logging_config.get('audit_enabled', False)
            else:
                logging_enabled = bool(logging_config)

        # Check for audit configuration
        if 'audit' in input:
            audit_config = input['audit']
            if isinstance(audit_config, dict):
                logging_enabled = audit_config.get('enabled', False) or \
                                  audit_config.get('active', False)
            else:
                logging_enabled = bool(audit_config)

        # Check for SIEM integration (indicates advanced logging)
        if 'siem_integration' in input or 'siemEnabled' in input:
            siem_enabled = input.get('siem_integration', input.get('siemEnabled', False))
            if siem_enabled:
                logging_enabled = True
                logging_details["siemIntegration"] = True

        # Check enterprise settings for logging
        if 'enterprise' in input:
            enterprise = input['enterprise']
            if isinstance(enterprise, dict):
                if enterprise.get('audit_log_enabled', False) or enterprise.get('event_logging', False):
                    logging_enabled = True

        return {
            criteria_key: logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
