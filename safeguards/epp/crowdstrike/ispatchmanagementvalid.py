def transform(input):
    """
    Ensure that processes exist and SLAs are met for vulnerability remediation.

    Parameters:
        input (dict): The JSON data containing crowdstrike API response

    Returns:
        dict: A dictionary with the isPatchManagementValid evaluation result
    """

    criteria_key = "isPatchManagementValid"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check patch management
        patch_management_enabled = False
        patch_details = {}

        # Check for patch management indicators
        if 'patchManagementEnabled' in input:
            patch_management_enabled = bool(input['patchManagementEnabled'])
        elif 'patches' in input:
            patches = input['patches'] if isinstance(input['patches'], list) else []
            patch_management_enabled = len(patches) > 0
            patch_details['patches'] = len(patches)
        elif 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            patch_policies = [p for p in policies if 'patch' in str(p).lower() or 'update' in str(p).lower()]
            patch_management_enabled = len(patch_policies) > 0
            patch_details['patchPolicies'] = len(patch_policies)
        elif 'updatePolicies' in input or 'sensorUpdatePolicies' in input:
            update_policies = input.get('updatePolicies', input.get('sensorUpdatePolicies', []))
            patch_management_enabled = bool(update_policies)
            patch_details['updatePolicies'] = update_policies
        elif 'enabled' in input:
            patch_management_enabled = bool(input['enabled'])

        return {
            criteria_key: patch_management_enabled,
            **patch_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
