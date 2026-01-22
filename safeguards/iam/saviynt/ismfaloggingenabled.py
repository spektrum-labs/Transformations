def transform(input):
    """
    Check MFA-specific logging is active

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the isMFALoggingEnabled evaluation result
    """

    criteria_key = "isMFALoggingEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        mfa_logging_enabled = False
        logging_details = {}

        # Check for runtimecontrols with authentication/MFA events
        if 'runtimecontrols' in input:
            controls = input['runtimecontrols']
            if isinstance(controls, list):
                # Filter for authentication-related events
                auth_events = [c for c in controls if any(
                    keyword in str(c).lower()
                    for keyword in ['authentication', 'mfa', 'login', 'factor', 'otp', 'totp', 'fido']
                )]
                mfa_logging_enabled = len(controls) > 0  # Any controls indicate logging is active
                logging_details['totalLogs'] = len(controls)
                logging_details['authenticationLogs'] = len(auth_events)
        elif 'auditLogs' in input:
            logs = input['auditLogs']
            if isinstance(logs, list):
                mfa_logging_enabled = len(logs) > 0
                logging_details['auditLogCount'] = len(logs)
        elif 'loggingEnabled' in input:
            mfa_logging_enabled = bool(input['loggingEnabled'])

        return {
            criteria_key: mfa_logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
