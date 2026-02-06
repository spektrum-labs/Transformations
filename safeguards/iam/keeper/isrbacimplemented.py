def transform(input):
    """
    Validates that role-based access control (RBAC) is implemented in Keeper.

    Parameters:
        input (dict): The JSON data from Keeper enterprise-role command response

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
        if 'data' in input:
            input = input['data']

        rbac_implemented = False
        rbac_details = {
            "roleCount": 0,
            "hasCustomRoles": False
        }

        # Check for roles array
        roles = input.get('roles', input.get('data', []))
        if isinstance(roles, list):
            rbac_details["roleCount"] = len(roles)
            # RBAC is implemented if there are roles defined
            rbac_implemented = len(roles) > 0

            # Check for custom (non-default) roles
            default_role_names = ['admin', 'administrator', 'user', 'default', 'everyone']
            custom_roles = [r for r in roles if isinstance(r, dict) and
                           r.get('name', '').lower() not in default_role_names]
            rbac_details["hasCustomRoles"] = len(custom_roles) > 0

        # Check for role-based permissions
        if 'permissions' in input:
            permissions = input['permissions']
            if isinstance(permissions, list) and len(permissions) > 0:
                rbac_implemented = True
            elif isinstance(permissions, dict) and permissions:
                rbac_implemented = True

        # Check for access control settings
        if 'access_control' in input or 'accessControl' in input:
            access_control = input.get('access_control', input.get('accessControl', {}))
            if isinstance(access_control, dict):
                rbac_implemented = access_control.get('enabled', False) or \
                                   access_control.get('rbac_enabled', False) or \
                                   bool(access_control.get('roles', []))

        # Check for teams (team-based access is a form of RBAC)
        if 'teams' in input:
            teams = input['teams']
            if isinstance(teams, list) and len(teams) > 0:
                rbac_implemented = True
                rbac_details["teamCount"] = len(teams)

        # Check for enforcement policies with role restrictions
        if 'enforcement' in input:
            enforcement = input['enforcement']
            if isinstance(enforcement, dict):
                if enforcement.get('role_enforcement', False) or \
                   enforcement.get('restrict_by_role', False):
                    rbac_implemented = True

        return {
            criteria_key: rbac_implemented,
            **rbac_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
