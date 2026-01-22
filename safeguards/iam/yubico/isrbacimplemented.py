def transform(input):
    """
    Validate RBAC is properly implemented

    Parameters:
        input (dict): The JSON data containing yubico API response

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

        # Check RBAC implementation
        rbac_implemented = False
        role_count = 0
        rbac_details = {}

        # Check for roles/groups
        if 'roles' in input:
            roles = input['roles'] if isinstance(input['roles'], list) else []
            role_count = len(roles)
            rbac_implemented = role_count > 0
            rbac_details['roles'] = roles
        elif 'groups' in input:
            groups = input['groups'] if isinstance(input['groups'], list) else []
            role_count = len(groups)
            rbac_implemented = role_count > 0
            rbac_details['groups'] = groups
        elif 'rbacEnabled' in input:
            rbac_implemented = bool(input['rbacEnabled'])
        elif 'roleBasedAccess' in input:
            rbac_implemented = bool(input['roleBasedAccess'])
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
