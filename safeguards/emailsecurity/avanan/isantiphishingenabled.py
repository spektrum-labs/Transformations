def transform(input):
    """
    Evaluates if anti-phishing protection is enabled in Avanan.
    
    Checks security events for phishing detection activity and validates
    that the anti-phishing engine is actively monitoring emails.

    Parameters:
        input (dict): The JSON data from Avanan security events endpoint.

    Returns:
        dict: A dictionary summarizing the anti-phishing status.
    """

    try:
        if 'response' in input:
            input = input['response']
        
        isAntiPhishingEnabled = False
        phishing_count = 0
        remediated_count = 0
        blocked_count = 0
        
        # Get security events from response
        security_events = input.get('securityEvents', input.get('responseData', []))
        if isinstance(security_events, list):
            # Platform is monitoring if we can access security events
            isAntiPhishingEnabled = True
            
            # Count phishing-related events
            phishing_keywords = ['phishing', 'credential', 'spear', 'whaling', 'bec', 
                               'impersonation', 'social engineering', 'spoofing']
            for event in security_events:
                event_type = (event.get('eventType', '') or event.get('securityEventType', '') or '').lower()
                threat_type = (event.get('threatType', '') or event.get('threat_type', '') or '').lower()
                
                if any(keyword in event_type or keyword in threat_type for keyword in phishing_keywords):
                    phishing_count += 1
                    
                    # Check remediation/action status
                    status = (event.get('status', '') or event.get('actionStatus', '') or '').lower()
                    action = (event.get('action', '') or event.get('actionTaken', '') or '').lower()
                    
                    if status in ['remediated', 'resolved', 'blocked', 'quarantined']:
                        remediated_count += 1
                    if action in ['block', 'blocked', 'quarantine', 'delete', 'removed']:
                        blocked_count += 1

        # Check for anti-phishing exceptions (indicates feature is configured)
        exceptions = input.get('exceptions', [])
        if isinstance(exceptions, list) and len(exceptions) > 0:
            isAntiPhishingEnabled = True

        policy_info = {
            "isAntiPhishingEnabled": isAntiPhishingEnabled,
            "phishingThreatsDetected": phishing_count,
            "phishingThreatsRemediated": remediated_count,
            "phishingThreatsBlocked": blocked_count,
            "totalEventsMonitored": len(security_events) if isinstance(security_events, list) else 0
        }
        return policy_info
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}

