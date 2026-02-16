def transform(input):
    """
    Validates that lifecycle management (provisioning/deprovisioning) is enabled in Keeper.

    Evaluates SCIM API response for user provisioning capabilities.
    SCIM endpoint: GET /Users

    CIS Control 6.1: Establish an Access Granting Process
    CIS Control 6.2: Establish an Access Revoking Process

    Parameters:
        input (dict): The JSON data from Keeper SCIM /Users endpoint response

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
        if 'data' in input:
            input = input['data']

        lifecycle_enabled = False
        lifecycle_details = {
            "totalUsers": 0,
            "activeUsers": 0,
            "inactiveUsers": 0,
            "scimProvisioned": False
        }

        # Check for SCIM Resources (standard SCIM response format)
        resources = input.get('Resources', input.get('resources', []))
        if isinstance(resources, list):
            lifecycle_details["totalUsers"] = len(resources)
            lifecycle_details["scimProvisioned"] = len(resources) > 0
            lifecycle_enabled = len(resources) > 0

            active_count = 0
            inactive_count = 0

            for user in resources:
                if isinstance(user, dict):
                    # SCIM uses 'active' boolean field
                    is_active = user.get('active', True)
                    if is_active:
                        active_count += 1
                    else:
                        inactive_count += 1

            lifecycle_details["activeUsers"] = active_count
            lifecycle_details["inactiveUsers"] = inactive_count

        # Check totalResults from SCIM response
        if 'totalResults' in input:
            lifecycle_details["totalUsers"] = input['totalResults']
            lifecycle_enabled = input['totalResults'] > 0

        # Check for users array (alternative response format)
        users = input.get('users', [])
        if isinstance(users, list) and len(users) > 0:
            lifecycle_details["totalUsers"] = len(users)
            lifecycle_enabled = True

            active_count = 0
            inactive_count = 0

            for user in users:
                if isinstance(user, dict):
                    status = user.get('status', user.get('active', 'active'))
                    if status in ['active', True, 'ACTIVE']:
                        active_count += 1
                    else:
                        inactive_count += 1

            lifecycle_details["activeUsers"] = active_count
            lifecycle_details["inactiveUsers"] = inactive_count

        # Check for SCIM configuration
        if 'scim_enabled' in input or 'scimEnabled' in input:
            scim_enabled = input.get('scim_enabled', input.get('scimEnabled', False))
            lifecycle_enabled = scim_enabled
            lifecycle_details["scimProvisioned"] = scim_enabled

        # Check for provisioning configuration
        if 'provisioning' in input:
            provisioning = input['provisioning']
            if isinstance(provisioning, dict):
                lifecycle_enabled = provisioning.get('enabled', False) or \
                                   provisioning.get('scim_enabled', False) or \
                                   provisioning.get('auto_provision', False)
                lifecycle_details["autoProvision"] = provisioning.get('auto_provision', False)
                lifecycle_details["autoDeprovision"] = provisioning.get('auto_deprovision', False)

        # Check for SSO/directory sync (indicates lifecycle management)
        if 'sso_services' in input or 'ssoServices' in input:
            sso = input.get('sso_services', input.get('ssoServices', []))
            if isinstance(sso, list) and len(sso) > 0:
                lifecycle_enabled = True
                lifecycle_details["ssoIntegration"] = True

        # Check for directory integration
        if 'directory_sync' in input or 'directorySync' in input:
            dir_sync = input.get('directory_sync', input.get('directorySync', {}))
            if isinstance(dir_sync, dict):
                lifecycle_enabled = dir_sync.get('enabled', False)
            else:
                lifecycle_enabled = bool(dir_sync)

        return {
            criteria_key: lifecycle_enabled,
            **lifecycle_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
