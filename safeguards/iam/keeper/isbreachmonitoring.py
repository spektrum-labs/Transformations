def transform(input):
    """
    Validates that breach monitoring (BreachWatch) is enabled in Keeper.

    Alias for isbreachmonitoringenabled.py - kept for backward compatibility.
    Evaluates Commander security-audit-report for BreachWatch status.
    Commander: security-audit-report

    NIST IA-5(18): Password Managers - Monitor for compromised credentials
    CIS Control 5.2: Use Unique Passwords

    Parameters:
        input (dict): The JSON data from Keeper Commander security-audit-report response

    Returns:
        dict: A dictionary with the isBreachWatchEnabled evaluation result
    """
    criteria_key = "isBreachWatchEnabled"

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
        monitoring_details = {
            "breachWatchEnabled": False,
            "breachedRecords": 0,
            "scannedRecords": 0,
            "highRiskPasswords": 0,
            "lastScanDate": None
        }

        # Check for BreachWatch feature (Keeper's breach monitoring)
        if 'breach_watch' in input or 'breachWatch' in input:
            breach_watch = input.get('breach_watch', input.get('breachWatch', {}))
            if isinstance(breach_watch, dict):
                breach_monitoring_enabled = breach_watch.get('enabled', False) or \
                                            breach_watch.get('active', False)
                monitoring_details["breachWatchEnabled"] = breach_monitoring_enabled
                monitoring_details["breachedRecords"] = breach_watch.get('breached_count',
                    breach_watch.get('breachedCount', 0))
                monitoring_details["scannedRecords"] = breach_watch.get('scanned_count',
                    breach_watch.get('scannedCount', 0))
                monitoring_details["lastScanDate"] = breach_watch.get('last_scan',
                    breach_watch.get('lastScan'))
            else:
                breach_monitoring_enabled = bool(breach_watch)
                monitoring_details["breachWatchEnabled"] = breach_monitoring_enabled

        # Check for dark web monitoring
        if 'dark_web_monitoring' in input or 'darkWebMonitoring' in input:
            dwm = input.get('dark_web_monitoring', input.get('darkWebMonitoring', {}))
            if isinstance(dwm, dict):
                breach_monitoring_enabled = dwm.get('enabled', False)
                monitoring_details["breachWatchEnabled"] = breach_monitoring_enabled
            else:
                breach_monitoring_enabled = bool(dwm)

        # Check security audit for breach indicators
        if 'security_audit' in input or 'securityAudit' in input:
            audit = input.get('security_audit', input.get('securityAudit', {}))
            if isinstance(audit, dict):
                # If breach data is present in audit, monitoring is enabled
                if 'breached_passwords' in audit or 'breachedPasswords' in audit:
                    breach_monitoring_enabled = True
                    monitoring_details["breachWatchEnabled"] = True
                    breached = audit.get('breached_passwords', audit.get('breachedPasswords', 0))
                    monitoring_details["breachedRecords"] = breached

                if 'high_risk_passwords' in audit or 'highRiskPasswords' in audit:
                    breach_monitoring_enabled = True
                    monitoring_details["breachWatchEnabled"] = True
                    high_risk = audit.get('high_risk_passwords', audit.get('highRiskPasswords', 0))
                    monitoring_details["highRiskPasswords"] = high_risk

                # Check BreachWatch specific fields
                bw_data = audit.get('breach_watch', audit.get('breachWatch', {}))
                if isinstance(bw_data, dict):
                    breach_monitoring_enabled = bw_data.get('enabled', True)  # If data exists, it's enabled
                    monitoring_details["breachWatchEnabled"] = breach_monitoring_enabled
                    monitoring_details["breachedRecords"] = bw_data.get('breached', 0)

        # Check enterprise settings for breach monitoring
        if 'enterprise' in input:
            enterprise = input['enterprise']
            if isinstance(enterprise, dict):
                if enterprise.get('breach_watch_enabled', False) or \
                   enterprise.get('breachWatchEnabled', False):
                    breach_monitoring_enabled = True
                    monitoring_details["breachWatchEnabled"] = True

        # Check enforcement policies for breach monitoring requirements
        if 'enforcement' in input:
            enforcement = input['enforcement']
            if isinstance(enforcement, dict):
                if enforcement.get('require_breach_watch', False) or \
                   enforcement.get('requireBreachWatch', False):
                    breach_monitoring_enabled = True
                    monitoring_details["breachWatchEnabled"] = True
                    monitoring_details["enforcedByPolicy"] = True

        # Check roles for BreachWatch enforcement
        if 'roles' in input:
            roles = input['roles']
            if isinstance(roles, list):
                for role in roles:
                    if isinstance(role, dict):
                        enforcement = role.get('enforcement', {})
                        if isinstance(enforcement, dict):
                            if enforcement.get('require_breach_watch', False):
                                breach_monitoring_enabled = True
                                monitoring_details["enforcedByPolicy"] = True
                                break

        # Check for compromised credentials alerts
        if 'alerts' in input or 'compromised_credentials' in input:
            alerts = input.get('alerts', input.get('compromised_credentials', []))
            if isinstance(alerts, list) and len(alerts) > 0:
                breach_monitoring_enabled = True
                monitoring_details["breachWatchEnabled"] = True
                monitoring_details["alertCount"] = len(alerts)

        return {
            criteria_key: breach_monitoring_enabled,
            **monitoring_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
