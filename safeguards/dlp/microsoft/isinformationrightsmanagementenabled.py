def transform(input):
    """
    Allows usage policies to contol content for requested actions like printing or forwarding

    Parameters:
        input (dict): The JSON data containing ms365_dlp API response

    Returns:
        dict: A dictionary with the isInformationRightsManagementEnabled evaluation result
    """

    criteria_key = "isInformationRightsManagementEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check information rights management
        irm_enabled = False
        irm_details = {}

        # Check for IRM indicators
        if 'irmEnabled' in input or 'informationRightsManagement' in input:
            irm_enabled = bool(input.get('irmEnabled', input.get('informationRightsManagement', False)))
        elif 'rightsManagement' in input or 'rms' in input:
            irm_enabled = bool(input.get('rightsManagement', input.get('rms', False)))
        elif 'enabled' in input:
            irm_enabled = bool(input['enabled'])
        elif 'templates' in input:
            templates = input['templates'] if isinstance(input['templates'], list) else []
            irm_enabled = len(templates) > 0
            irm_details['templates'] = len(templates)

        return {
            criteria_key: irm_enabled,
            **irm_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
