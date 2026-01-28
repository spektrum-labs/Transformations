def transform(input):
    """
    Validates that privileged access management (PAM) is enabled in Keeper.

    Parameters:
        input (dict): The JSON data from Keeper enterprise-role command response

    Returns:
        dict: A dictionary with the isPAMEnabled evaluation result
    """
    criteria_key = "isPAMEnabled"

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

        pam_enabled = False
        pam_details = {}

        # Check for PAM-specific features
        if 'pam_enabled' in input or 'pamEnabled' in input:
            pam_enabled = bool(input.get('pam_enabled', input.get('pamEnabled', False)))

        # Check for KeeperPAM module
        if 'keeper_pam' in input or 'keeperPAM' in input:
            pam_config = input.get('keeper_pam', input.get('keeperPAM', {}))
            if isinstance(pam_config, dict):
                pam_enabled = pam_config.get('enabled', False) or pam_config.get('active', False)
            else:
                pam_enabled = bool(pam_config)

        # Check for privileged access indicators
        if 'privileged_access' in input or 'privilegedAccess' in input:
            priv_access = input.get('privileged_access', input.get('privilegedAccess', {}))
            if isinstance(priv_access, dict):
                pam_enabled = priv_access.get('enabled', False)
                pam_details['sessionRecording'] = priv_access.get('session_recording', False)
                pam_details['connectionManager'] = priv_access.get('connection_manager', False)
            else:
                pam_enabled = bool(priv_access)

        # Check enforcement policies for PAM features
        if 'enforcement' in input or 'enforcementPolicies' in input:
            enforcement = input.get('enforcement', input.get('enforcementPolicies', {}))
            if isinstance(enforcement, dict):
                # PAM-related enforcement policies
                pam_policies = [
                    'restrict_record_types',
                    'require_session_recording',
                    'restrict_sharing',
                    'restrict_export',
                    'require_account_recovery'
                ]
                for policy in pam_policies:
                    if enforcement.get(policy, False):
                        pam_enabled = True
                        pam_details[policy] = True
            elif isinstance(enforcement, list):
                # Check list of enforcement policies
                for policy in enforcement:
                    if isinstance(policy, dict):
                        if policy.get('type', '').lower() in ['pam', 'privileged', 'session']:
                            pam_enabled = True

        # Check for secrets management (part of PAM)
        if 'secrets_manager' in input or 'secretsManager' in input:
            secrets = input.get('secrets_manager', input.get('secretsManager', {}))
            if isinstance(secrets, dict):
                pam_enabled = secrets.get('enabled', False)
                pam_details['secretsManager'] = True
            else:
                pam_enabled = bool(secrets)

        # Check for connection resources (indicates PAM usage)
        if 'connections' in input or 'resources' in input:
            connections = input.get('connections', input.get('resources', []))
            if isinstance(connections, list) and len(connections) > 0:
                pam_enabled = True
                pam_details['connectionCount'] = len(connections)

        # Check roles for admin/PAM capabilities
        roles = input.get('roles', [])
        if isinstance(roles, list):
            for role in roles:
                if isinstance(role, dict):
                    role_name = role.get('name', '').lower()
                    if 'admin' in role_name or 'pam' in role_name or 'privileged' in role_name:
                        pam_enabled = True
                        break

        return {
            criteria_key: pam_enabled,
            **pam_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
