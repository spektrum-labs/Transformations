def transform(input):
    """
    Allows for managed just-in-time privileged access to resources.

    Parameters:
        input (dict): The JSON data containing ms365_iam API response

    Returns:
        dict: A dictionary with the isPrivilegedIdentityManagementEnabled evaluation result
    """

    criteria_key = "isPrivilegedIdentityManagementEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check PAM implementation
        pam_enabled = False
        pam_details = {}

        # Check for PAM indicators
        if 'pamEnabled' in input or 'privilegedAccessManagement' in input:
            pam_enabled = bool(input.get('pamEnabled', input.get('privilegedAccessManagement', False)))
        elif 'privilegedAccounts' in input:
            accounts = input['privilegedAccounts'] if isinstance(input['privilegedAccounts'], list) else []
            pam_enabled = len(accounts) > 0
            pam_details['privilegedAccounts'] = accounts
        elif 'enabled' in input:
            pam_enabled = bool(input['enabled'])
        elif 'vaults' in input or 'safes' in input:
            vaults = input.get('vaults', input.get('safes', []))
            pam_enabled = len(vaults) > 0 if isinstance(vaults, list) else bool(vaults)
            pam_details['vaults'] = vaults

        return {
            criteria_key: pam_enabled,
            **pam_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
