def transform(input):
    """
    Check provisioning/deprovisioning workflows exist

    Parameters:
        input (dict): The JSON data containing Saviynt API response

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

        # Check for userdetails indicating user management is in place
        if 'userdetails' in input:
            users = input['userdetails']
            if isinstance(users, list):
                lifecycle_enabled = len(users) > 0
                lifecycle_details['userCount'] = len(users)
                # Check for lifecycle indicators in user data
                users_with_status = [u for u in users if 'statuskey' in u or 'status' in u]
                lifecycle_details['usersWithStatusTracking'] = len(users_with_status)
        elif 'users' in input:
            users = input['users']
            if isinstance(users, list):
                lifecycle_enabled = len(users) > 0
                lifecycle_details['userCount'] = len(users)
        elif 'totalcount' in input and input.get('totalcount', 0) > 0:
            lifecycle_enabled = True
            lifecycle_details['totalUsers'] = input['totalcount']
        elif 'lifecycleEnabled' in input:
            lifecycle_enabled = bool(input['lifecycleEnabled'])

        return {
            criteria_key: lifecycle_enabled,
            **lifecycle_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
