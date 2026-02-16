def transform(input):
    """
    Checks if Role-Based Access Control (RBAC) is implemented in Aquera

    Parameters:
        input (dict): The JSON data containing Aquera groups/roles API response

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
        rbac_details = {}

        # Check groups/roles
        groups = input.get('groups', input.get('roles', input.get('data', input.get('value', []))))
        if isinstance(groups, list):
            rbac_details['totalGroups'] = len(groups)
            rbac_implemented = len(groups) > 0

            # Check for role assignments
            assigned = [g for g in groups if g.get('members', g.get('memberCount', 0))]
            rbac_details['groupsWithMembers'] = len(assigned)

        # Check for role definitions
        elif 'roleDefinitions' in input:
            roles = input['roleDefinitions']
            if isinstance(roles, list):
                rbac_details['totalRoles'] = len(roles)
                rbac_implemented = len(roles) > 0

        # Check for access policies
        elif 'accessPolicies' in input:
            policies = input['accessPolicies']
            if isinstance(policies, list):
                rbac_details['accessPolicies'] = len(policies)
                rbac_implemented = len(policies) > 0

        return {
            criteria_key: rbac_implemented,
            **rbac_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
