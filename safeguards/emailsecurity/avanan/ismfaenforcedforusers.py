def transform(input):
    """
    Evaluates if MFA is enforced for users accessing Avanan.
    
    MFA is typically enforced via the identity provider (IdP) when SSO is enabled.

    Parameters:
        input (dict): The JSON data from Avanan audit logs endpoint.

    Returns:
        dict: A dictionary summarizing the MFA information.
    """

    try:
        if 'response' in input:
            input = input['response']
        
        isMFAEnforcedForUsers = False
        sso_enabled = False

        # Check for explicit MFA status
        if 'isMFAEnforcedForUsers' in input:
            isMFAEnforcedForUsers = input['isMFAEnforcedForUsers']
        
        # Check for SSO - if SSO is enabled, MFA is typically handled by IdP
        if input.get('ssoEnabled') or input.get('samlEnabled'):
            sso_enabled = True
            isMFAEnforcedForUsers = True
        
        # Check audit logs for MFA or SSO activity
        audit_logs = input.get('auditLogs', input.get('responseData', []))
        if isinstance(audit_logs, list):
            mfa_indicators = ['mfa', 'multi-factor', '2fa', 'two-factor', 'authenticator',
                            'otp', 'one-time password', 'verification code']
            sso_indicators = ['sso', 'saml', 'okta', 'azure ad', 'onelogin', 'ping',
                            'identity provider', 'idp', 'federated']
            
            for log in audit_logs:
                action = (log.get('action', '') or log.get('eventType', '') or '').lower()
                details = (log.get('details', '') or log.get('description', '') or '').lower()
                
                if any(indicator in action or indicator in details for indicator in mfa_indicators):
                    isMFAEnforcedForUsers = True
                    break
                if any(indicator in action or indicator in details for indicator in sso_indicators):
                    sso_enabled = True
                    isMFAEnforcedForUsers = True
                    break

        mfa_info = {
            "isMFAEnforcedForUsers": isMFAEnforcedForUsers,
            "ssoEnabled": sso_enabled
        }
        return mfa_info
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}

