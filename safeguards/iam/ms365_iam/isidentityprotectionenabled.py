def transform(input):
    """
    Allows endpoint vulnerability visibility.

    Parameters:
        input (dict): The JSON data containing ms365_iam API response

    Returns:
        dict: A dictionary with the isIdentityProtectionEnabled evaluation result
    """

    criteria_key = "isIdentityProtectionEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Generic validation logic
        is_valid = False
        details = {}

        # Check for common boolean indicators
        if 'enabled' in input:
            is_valid = bool(input['enabled'])
        elif 'configured' in input:
            is_valid = bool(input['configured'])
        elif 'status' in input:
            status = str(input['status']).lower()
            is_valid = status in ['enabled', 'active', 'on', 'true', 'success']
            details['status'] = status
        elif 'state' in input:
            state = str(input['state']).lower()
            is_valid = state in ['enabled', 'active', 'on', 'true', 'success']
            details['state'] = state
        elif isinstance(input, bool):
            is_valid = input
        elif isinstance(input, list):
            is_valid = len(input) > 0
            details['count'] = len(input)
        elif isinstance(input, dict) and len(input) > 0:
            is_valid = True
            details['data'] = input

        return {
            criteria_key: is_valid,
            **details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
