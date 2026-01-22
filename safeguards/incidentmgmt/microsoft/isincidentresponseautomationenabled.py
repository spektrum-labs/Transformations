def transform(input):
    """
    Allows for orchestrated responses to incidents.

    Parameters:
        input (dict): The JSON data containing ms365_incident API response

    Returns:
        dict: A dictionary with the isIncidentResponseAutomationEnabled evaluation result
    """

    criteria_key = "isIncidentResponseAutomationEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check incident/security feature
        is_enabled = False
        feature_details = {}

        # Check for feature enablement
        if 'enabled' in input:
            is_enabled = bool(input['enabled'])
        elif 'configured' in input:
            is_enabled = bool(input['configured'])
        elif 'integrated' in input or 'integration' in input:
            is_enabled = bool(input.get('integrated', input.get('integration', False)))
        elif 'status' in input:
            status = str(input['status']).lower()
            is_enabled = status in ['enabled', 'active', 'on']
            feature_details['status'] = status
        elif 'automation' in input or 'automationEnabled' in input:
            is_enabled = bool(input.get('automation', input.get('automationEnabled', False)))
        elif isinstance(input, list):
            is_enabled = len(input) > 0
            feature_details['count'] = len(input)

        return {
            criteria_key: is_enabled,
            **feature_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
