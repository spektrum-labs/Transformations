def transform(input):
    """
    Evaluates if SSO is enabled for Avanan platform access.
    
    Checks audit logs for SSO/SAML login activity and configuration.

    Parameters:
        input (dict): The JSON data from Avanan audit logs endpoint.

    Returns:
        dict: A dictionary summarizing the SSO information.
    """

    try:
        isSSOEnabled = False

        if 'response' in input:
            input = input['response']
        if 'result' in input:
            input = input['result']

        # Check for explicit SSO status
        if input.get('ssoEnabled') or input.get('samlEnabled'):
            isSSOEnabled = True
        
        # Check audit logs for SSO activity
        audit_logs = input.get('auditLogs', input.get('responseData', []))
        if isinstance(audit_logs, list) and len(audit_logs) > 0:
            sso_indicators = ['sso', 'saml', 'okta', 'azure ad', 'onelogin', 'ping', 
                            'identity provider', 'idp', 'federated', 'single sign-on']
            for log in audit_logs:
                action = (log.get('action', '') or log.get('eventType', '') or '').lower()
                details = (log.get('details', '') or log.get('description', '') or '').lower()
                
                if any(indicator in action or indicator in details for indicator in sso_indicators):
                    isSSOEnabled = True
                    break

        sso_info = {
            "isSSOEnabled": isSSOEnabled
        }
        return sso_info
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}

