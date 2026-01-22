def transform(input):
    """
    Check IAM-specific audit logging

    Parameters:
        input (dict): The JSON data containing Saviynt API response

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

        iam_logging_enabled = False
        logging_details = {}

        # Check for runtimecontrols with IAM-related events
        if 'runtimecontrols' in input:
            controls = input['runtimecontrols']
            if isinstance(controls, list):
                # Filter for IAM-related events
                iam_events = [c for c in controls if any(
                    keyword in str(c).lower()
                    for keyword in ['user', 'role', 'access', 'permission', 'entitlement', 'identity']
                )]
                iam_logging_enabled = len(controls) > 0  # Any controls indicate logging is active
                logging_details['totalLogs'] = len(controls)
                logging_details['iamRelatedLogs'] = len(iam_events)
        elif 'auditLogs' in input:
            logs = input['auditLogs']
            if isinstance(logs, list):
                iam_logging_enabled = len(logs) > 0
                logging_details['auditLogCount'] = len(logs)
        elif 'loggingEnabled' in input:
            iam_logging_enabled = bool(input['loggingEnabled'])

        return {
            criteria_key: iam_logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
