def transform(input):
    """
    Validate proper provisioning and deprovisioning processes exist

    Parameters:
        input (dict): The JSON data containing strata API response

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

        # Check lifecycle management
        lifecycle_enabled = False
        lifecycle_details = {}

        # Check for lifecycle/provisioning indicators
        if 'lifecycleManagement' in input or 'provisioningEnabled' in input:
            lifecycle_enabled = bool(input.get('lifecycleManagement', input.get('provisioningEnabled', False)))
        elif 'automatedProvisioning' in input:
            lifecycle_enabled = bool(input['automatedProvisioning'])
        elif 'enabled' in input:
            lifecycle_enabled = bool(input['enabled'])
        elif 'workflows' in input:
            workflows = input['workflows'] if isinstance(input['workflows'], list) else []
            lifecycle_enabled = len(workflows) > 0
            lifecycle_details['workflows'] = workflows
        elif 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            lifecycle_enabled = len(policies) > 0
            lifecycle_details['policies'] = policies

        return {
            criteria_key: lifecycle_enabled,
            **lifecycle_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
