def transform(input):
    """
    Checks if Information Rights Management (IRM) is enabled in Cato Networks

    Parameters:
        input (dict): The JSON data containing Cato IRM policy API response

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

        irm_enabled = False
        irm_details = {}

        # Cato GraphQL response structure
        data = input.get('data', input)
        policy_data = data.get('policy', data)

        # Check for IRM/content control policies
        if 'contentControl' in policy_data:
            content = policy_data['contentControl']
            if isinstance(content, dict):
                irm_enabled = content.get('enabled', False)
                irm_details['contentControl'] = content
        elif 'appTenantRestriction' in policy_data:
            restriction = policy_data['appTenantRestriction']
            if isinstance(restriction, dict):
                policy = restriction.get('policy', {})
                irm_enabled = policy.get('enabled', False)
                irm_details['appTenantRestriction'] = restriction
        elif 'irm' in input:
            irm_enabled = bool(input['irm'])
            irm_details['irm'] = input['irm']
        elif 'enabled' in input:
            irm_enabled = bool(input['enabled'])

        return {
            criteria_key: irm_enabled,
            **irm_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
