def transform(input):
    """
    Validates that MFA/2FA coverage is complete for all users in Keeper.

    Evaluates Commander security-audit-report or SCIM user data for 2FA status.
    Commander: security-audit-report
    SCIM: GET /Users

    CIS Control 6.3: Require MFA for Externally-Exposed Applications
    CIS Control 6.4: Require MFA for Remote Network Access
    CIS Control 6.5: Require MFA for Administrative Access

    Parameters:
        input (dict): The JSON data from Keeper security-audit-report or user data response

    Returns:
        dict: A dictionary with the isMFACoverageComplete evaluation result
    """
    criteria_key = "isMFACoverageComplete"

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

        mfa_complete = False
        mfa_details = {
            "totalUsers": 0,
            "mfaEnabled": 0,
            "mfaDisabled": 0,
            "mfaCoveragePercentage": 0.0,
            "adminsMfaEnabled": 0,
            "adminsTotal": 0
        }

        # Check for two-factor status in security audit
        if 'two_factor_status' in input or 'twoFactorStatus' in input:
            tfa = input.get('two_factor_status', input.get('twoFactorStatus', {}))
            if isinstance(tfa, dict):
                enabled = tfa.get('enabled', tfa.get('enabled_count', 0))
                disabled = tfa.get('disabled', tfa.get('disabled_count', 0))
                total = tfa.get('total', enabled + disabled)

                mfa_details["mfaEnabled"] = enabled
                mfa_details["mfaDisabled"] = disabled
                mfa_details["totalUsers"] = total

                if total > 0:
                    coverage = (enabled / total) * 100
                    mfa_details["mfaCoveragePercentage"] = round(coverage, 2)
                    mfa_complete = coverage == 100  # 100% coverage required

        # Check security audit data
        if 'security_audit' in input or 'securityAudit' in input:
            audit = input.get('security_audit', input.get('securityAudit', {}))
            if isinstance(audit, dict):
                tfa_data = audit.get('two_factor', audit.get('twoFactor',
                          audit.get('mfa', {})))
                if isinstance(tfa_data, dict):
                    enabled = tfa_data.get('enabled', tfa_data.get('enabled_count', 0))
                    total = tfa_data.get('total', 0)

                    mfa_details["mfaEnabled"] = enabled
                    mfa_details["totalUsers"] = total
                    if total > 0:
                        mfa_details["mfaDisabled"] = total - enabled
                        coverage = (enabled / total) * 100
                        mfa_details["mfaCoveragePercentage"] = round(coverage, 2)
                        mfa_complete = coverage == 100

        # Check users array
        users = input.get('users', input.get('Resources', []))
        if isinstance(users, list) and len(users) > 0:
            mfa_details["totalUsers"] = len(users)
            enabled_count = 0
            admin_total = 0
            admin_mfa = 0

            for user in users:
                if isinstance(user, dict):
                    # Check MFA status
                    mfa_enabled = user.get('two_factor_enabled', user.get('twoFactorEnabled',
                                 user.get('mfa_enabled', user.get('mfaEnabled', False))))
                    if mfa_enabled:
                        enabled_count += 1

                    # Check if admin
                    is_admin = user.get('is_admin', user.get('isAdmin',
                              user.get('role', '').lower() in ['admin', 'administrator']))
                    if is_admin:
                        admin_total += 1
                        if mfa_enabled:
                            admin_mfa += 1

            mfa_details["mfaEnabled"] = enabled_count
            mfa_details["mfaDisabled"] = len(users) - enabled_count
            mfa_details["adminsTotal"] = admin_total
            mfa_details["adminsMfaEnabled"] = admin_mfa

            if len(users) > 0:
                coverage = (enabled_count / len(users)) * 100
                mfa_details["mfaCoveragePercentage"] = round(coverage, 2)
                mfa_complete = coverage == 100

        # Check for MFA policy enforcement
        if 'enforcement' in input:
            enforcement = input['enforcement']
            if isinstance(enforcement, dict):
                if enforcement.get('require_two_factor', False) or \
                   enforcement.get('mfa_required', False):
                    # If MFA is required by policy, assume compliant
                    # (non-compliant users would be locked out)
                    mfa_complete = True
                    mfa_details["enforcedByPolicy"] = True

        # Check roles for MFA enforcement
        if 'roles' in input:
            roles = input['roles']
            if isinstance(roles, list):
                all_roles_enforce_mfa = True
                for role in roles:
                    if isinstance(role, dict):
                        enforcement = role.get('enforcement', {})
                        if isinstance(enforcement, dict):
                            if not enforcement.get('require_two_factor', False):
                                all_roles_enforce_mfa = False
                if all_roles_enforce_mfa and len(roles) > 0:
                    mfa_complete = True
                    mfa_details["enforcedByAllRoles"] = True

        # Calculate admin MFA coverage separately (critical per CIS 6.5)
        if mfa_details["adminsTotal"] > 0:
            admin_coverage = (mfa_details["adminsMfaEnabled"] / mfa_details["adminsTotal"]) * 100
            mfa_details["adminMfaCoveragePercentage"] = round(admin_coverage, 2)
            # Even if overall is not 100%, flag if admins are not fully covered
            mfa_details["adminsMfaComplete"] = admin_coverage == 100

        return {
            criteria_key: mfa_complete,
            **mfa_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
