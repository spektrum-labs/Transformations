def transform(input):
    """
    Checks if identity lifecycle management is enabled in Aquera

    Parameters:
        input (dict): The JSON data containing Aquera workflows API response

    Returns:
        dict: A dictionary with the isLifeCycleManagementEnabled evaluation result
    """

    criteria_key = "isLifeCycleManagementEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        lifecycle_enabled = False
        lifecycle_details = {}

        # Check workflows/provisioning
        workflows = input.get('workflows', input.get('data', input.get('value', [])))
        if isinstance(workflows, list):
            lifecycle_details['totalWorkflows'] = len(workflows)

            active = [w for w in workflows if w.get('status', '').lower() in ['active', 'enabled'] or w.get('enabled', False)]
            lifecycle_details['activeWorkflows'] = len(active)
            lifecycle_enabled = len(active) > 0

        # Check connectors for provisioning
        elif 'connectors' in input:
            connectors = input['connectors']
            if isinstance(connectors, list):
                provisioning = [c for c in connectors if c.get('type', '').lower() in ['provisioning', 'lifecycle', 'scim']]
                lifecycle_details['totalConnectors'] = len(connectors)
                lifecycle_details['provisioningConnectors'] = len(provisioning)
                lifecycle_enabled = len(provisioning) > 0

        # Check provisioning policies
        elif 'provisioningPolicies' in input:
            policies = input['provisioningPolicies']
            if isinstance(policies, list):
                lifecycle_details['provisioningPolicies'] = len(policies)
                lifecycle_enabled = len(policies) > 0

        return {
            criteria_key: lifecycle_enabled,
            **lifecycle_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
