def transform(input):
    """
    Make sure that capabilities for removable media are restricted appropriately

    Parameters:
        input (dict): The JSON data containing synqly_crowdstrike API response

    Returns:
        dict: A dictionary with the isRemovableMediaControlled evaluation result
    """

    criteria_key = "isRemovableMediaControlled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check removable media control
        media_controlled = False
        control_details = {}

        # Check for media control indicators
        if 'removableMediaControl' in input or 'mediaControlEnabled' in input:
            media_controlled = bool(input.get('removableMediaControl', input.get('mediaControlEnabled', False)))
        elif 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            media_policies = [p for p in policies if 'usb' in str(p).lower() or 'removable' in str(p).lower() or 'media' in str(p).lower()]
            media_controlled = len(media_policies) > 0
            control_details['mediaPolicies'] = len(media_policies)
        elif 'deviceControl' in input:
            media_controlled = bool(input['deviceControl'])
            control_details['deviceControl'] = input['deviceControl']
        elif 'enabled' in input:
            media_controlled = bool(input['enabled'])

        return {
            criteria_key: media_controlled,
            **control_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
