def transform(input):
    """
    Validates that breach monitoring (BreachWatch) is enabled in Keeper.

    Parameters:
        input (dict): The JSON data from Keeper security-audit-report command response

    Returns:
        dict: A dictionary with the isBreachMonitoringEnabled evaluation result
    """
    criteria_key = "isBreachMonitoringEnabled"

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

        breach_monitoring_enabled = False
        monitoring_details = {}

        # Check for BreachWatch feature (Keeper's breach monitoring)
        if 'breach_watch' in input or 'breachWatch' in input:
            breach_watch = input.get('breach_watch', input.get('breachWatch', {}))
            if isinstance(breach_watch, dict):
                breach_monitoring_enabled = breach_watch.get('enabled', False) or \
                                            breach_watch.get('active', False)
                monitoring_details['breachedRecords'] = breach_watch.get('breached_count', 0)
                monitoring_details['scannedRecords'] = breach_watch.get('scanned_count', 0)
            else:
                breach_monitoring_enabled = bool(breach_watch)

        # Check for dark web monitoring
        if 'dark_web_monitoring' in input or 'darkWebMonitoring' in input:
            dwm = input.get('dark_web_monitoring', input.get('darkWebMonitoring', {}))
            if isinstance(dwm, dict):
                breach_monitoring_enabled = dwm.get('enabled', False)
            else:
                breach_monitoring_enabled = bool(dwm)

        # Check security audit for breach indicators
        if 'securityAudit' in input or 'security_audit' in input:
            audit = input.get('securityAudit', input.get('security_audit', {}))
            if isinstance(audit, dict):
                # If breach data is present in audit, monitoring is enabled
                if 'breached_passwords' in audit or 'breachedPasswords' in audit:
                    breach_monitoring_enabled = True
                    breached = audit.get('breached_passwords', audit.get('breachedPasswords', 0))
                    monitoring_details['breachedPasswords'] = breached

                if 'high_risk_passwords' in audit or 'highRiskPasswords' in audit:
                    breach_monitoring_enabled = True
                    high_risk = audit.get('high_risk_passwords', audit.get('highRiskPasswords', 0))
                    monitoring_details['highRiskPasswords'] = high_risk

        # Check enterprise settings for breach monitoring
        if 'enterprise' in input:
            enterprise = input['enterprise']
            if isinstance(enterprise, dict):
                if enterprise.get('breach_watch_enabled', False) or \
                   enterprise.get('breachWatchEnabled', False):
                    breach_monitoring_enabled = True

        # Check enforcement policies for breach monitoring requirements
        if 'enforcement' in input:
            enforcement = input['enforcement']
            if isinstance(enforcement, dict):
                if enforcement.get('require_breach_watch', False) or \
                   enforcement.get('requireBreachWatch', False):
                    breach_monitoring_enabled = True
                    monitoring_details['enforcedByPolicy'] = True

        # Check for compromised credentials alerts
        if 'alerts' in input or 'compromised_credentials' in input:
            alerts = input.get('alerts', input.get('compromised_credentials', []))
            if isinstance(alerts, list) and len(alerts) > 0:
                breach_monitoring_enabled = True
                monitoring_details['alertCount'] = len(alerts)

        return {
            criteria_key: breach_monitoring_enabled,
            **monitoring_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
