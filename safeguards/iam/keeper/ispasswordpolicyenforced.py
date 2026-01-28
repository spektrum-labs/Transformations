def transform(input):
    """
    Validates that password policies are enforced in Keeper.

    Parameters:
        input (dict): The JSON data from Keeper security-audit-report command response

    Returns:
        dict: A dictionary with the isPasswordPolicyEnforced evaluation result
    """
    criteria_key = "isPasswordPolicyEnforced"

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

        policy_enforced = False
        policy_details = {}

        # Check for password policy configuration
        if 'password_policy' in input or 'passwordPolicy' in input:
            policy = input.get('password_policy', input.get('passwordPolicy', {}))
            if isinstance(policy, dict):
                policy_enforced = policy.get('enabled', False) or policy.get('enforced', False)
                policy_details['minLength'] = policy.get('min_length', policy.get('minLength', 0))
                policy_details['requireUppercase'] = policy.get('require_uppercase', False)
                policy_details['requireNumbers'] = policy.get('require_numbers', False)
                policy_details['requireSpecial'] = policy.get('require_special', False)

        # Check enforcement policies
        if 'enforcement' in input:
            enforcement = input['enforcement']
            if isinstance(enforcement, dict):
                if enforcement.get('master_password_minimum_length', 0) > 0:
                    policy_enforced = True
                    policy_details['minMasterPasswordLength'] = enforcement['master_password_minimum_length']
                if enforcement.get('require_two_factor', False):
                    policy_details['require2FA'] = True
                if enforcement.get('restrict_record_types', False):
                    policy_enforced = True

        # Check security audit results for password health
        if 'securityAudit' in input or 'security_audit' in input:
            audit = input.get('securityAudit', input.get('security_audit', {}))
            if isinstance(audit, dict):
                # If we have audit data with scoring, policies are being enforced
                if 'security_score' in audit or 'securityScore' in audit:
                    policy_enforced = True
                    policy_details['securityScore'] = audit.get('security_score', audit.get('securityScore', 0))

                # Check for weak password indicators
                weak_passwords = audit.get('weak_passwords', audit.get('weakPasswords', 0))
                reused_passwords = audit.get('reused_passwords', audit.get('reusedPasswords', 0))
                policy_details['weakPasswords'] = weak_passwords
                policy_details['reusedPasswords'] = reused_passwords

        # Check for password strength requirements in roles
        roles = input.get('roles', [])
        if isinstance(roles, list):
            for role in roles:
                if isinstance(role, dict):
                    enforcement = role.get('enforcement', {})
                    if isinstance(enforcement, dict):
                        if enforcement.get('master_password_minimum_length', 0) > 0:
                            policy_enforced = True
                            break

        # Check for enterprise-wide password policies
        if 'enterprise' in input:
            enterprise = input['enterprise']
            if isinstance(enterprise, dict):
                if enterprise.get('password_policy_enabled', False):
                    policy_enforced = True
                if enterprise.get('minimum_password_length', 0) > 0:
                    policy_enforced = True
                    policy_details['enterpriseMinLength'] = enterprise['minimum_password_length']

        return {
            criteria_key: policy_enforced,
            **policy_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
