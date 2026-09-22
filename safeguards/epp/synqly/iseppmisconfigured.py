def transform(input):
    """
    EPP vendor health check fails

    Parameters:
        input (dict): The JSON data containing synqly API response

    Returns:
        dict: A dictionary with the isEPPMisconfigured evaluation result
    """

    criteria_key = "isEPPMisconfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check for enabled/configured state
        is_enabled = False
        config_details = {}

        # Check common configuration fields
        if 'enabled' in input:
            is_enabled = bool(input['enabled'])
        elif 'isEnabled' in input:
            is_enabled = bool(input['isEnabled'])
        elif 'state' in input:
            is_enabled = str(input['state']).lower() in ['enabled', 'active', 'on']
            config_details['state'] = input['state']
        elif 'status' in input:
            is_enabled = str(input['status']).lower() in ['enabled', 'active', 'on']
            config_details['status'] = input['status']
        elif 'configured' in input:
            is_enabled = bool(input['configured'])
        elif isinstance(input, list) and len(input) > 0:
            is_enabled = True
            config_details['count'] = len(input)
        # The old final branch -- "elif isinstance(input, dict) and len(input) > 0:
        # is_enabled = True" -- treated ANY non-empty dict as proof of this state, so
        # an auth-error envelope or any unrecognised body with any key at all satisfied
        # the criterion. Removed: the response must actually name one of the
        # recognised fields above.

        return {
            criteria_key: is_enabled,
            **config_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
