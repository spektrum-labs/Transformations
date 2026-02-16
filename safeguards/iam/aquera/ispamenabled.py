def transform(input):
    """
    Checks if Privileged Access Management (PAM) is enabled in Aquera

    Parameters:
        input (dict): The JSON data containing Aquera connectors/policies API response

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

        pam_enabled = False
        pam_details = {}

        # Check connectors for PAM-related integrations
        connectors = input.get('connectors', input.get('data', input.get('value', [])))
        if isinstance(connectors, list):
            lifecycle_details_count = len(connectors)
            pam_connectors = [c for c in connectors if c.get('type', '').lower() in ['pam', 'privileged', 'vault'] or 'pam' in c.get('name', '').lower() or 'privileged' in c.get('name', '').lower()]
            pam_details['totalConnectors'] = lifecycle_details_count
            pam_details['pamConnectors'] = len(pam_connectors)
            pam_enabled = len(pam_connectors) > 0

        # Check for PAM policies
        elif 'policies' in input:
            policies = input['policies']
            if isinstance(policies, list):
                pam_policies = [p for p in policies if p.get('type', '').lower() in ['pam', 'privileged'] or 'privileged' in p.get('name', '').lower()]
                pam_details['totalPolicies'] = len(policies)
                pam_details['pamPolicies'] = len(pam_policies)
                pam_enabled = len(pam_policies) > 0

        # Check for privileged access settings
        elif 'privilegedAccess' in input:
            pa = input['privilegedAccess']
            pam_enabled = pa.get('enabled', False) if isinstance(pa, dict) else bool(pa)
            pam_details['privilegedAccess'] = pa

        return {
            criteria_key: pam_enabled,
            **pam_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
