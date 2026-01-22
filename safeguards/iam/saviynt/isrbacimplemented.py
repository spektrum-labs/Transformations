def transform(input):
    """
    Validate roles are defined for RBAC

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the isRBACImplemented evaluation result
    """

    criteria_key = "isRBACImplemented"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        rbac_implemented = False
        role_count = 0
        rbac_details = {}

        # Check for roles array (Saviynt getRoles response)
        if 'roles' in input:
            roles = input['roles']
            if isinstance(roles, list):
                role_count = len(roles)
                rbac_implemented = role_count > 0
                rbac_details['roles'] = roles[:10] if len(roles) > 10 else roles  # Limit response size
        elif 'totalcount' in input and input.get('totalcount', 0) > 0:
            role_count = input['totalcount']
            rbac_implemented = role_count > 0
        elif isinstance(input, list):
            role_count = len(input)
            rbac_implemented = role_count > 0

        return {
            criteria_key: rbac_implemented,
            "roleCount": role_count,
            **rbac_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
