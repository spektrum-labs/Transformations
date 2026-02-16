def transform(input):
    """
    Validates that SIEM integration is enabled for security event monitoring in Keeper.

    Evaluates Commander audit-log configuration or enterprise settings.
    Commander: audit-log

    NIST AC-2(4): Automated Audit Actions
    CIS Control 8: Audit Log Management

    Parameters:
        input (dict): The JSON data from Keeper Commander audit-log or enterprise settings response

    Returns:
        dict: A dictionary with the isSIEMIntegrationEnabled evaluation result
    """
    criteria_key = "isSIEMIntegrationEnabled"

    # Known SIEM targets supported by Keeper
    KNOWN_SIEM_TARGETS = [
        'splunk', 'sumo', 'sumologic', 'azure', 'azure-la', 'sentinel',
        'syslog', 'qradar', 'elastic', 'elasticsearch', 'datadog',
        'chronicle', 'crowdstrike', 'devo', 'exabeam', 'logrhythm',
        'servicenow', 's3', 'aws-s3'
    ]

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

        siem_enabled = False
        siem_details = {
            "integrationConfigured": False,
            "siemTarget": None,
            "lastEventTime": None,
            "eventCount": 0
        }

        # Check for SIEM integration flag
        if 'siem_integration' in input or 'siemIntegration' in input:
            siem = input.get('siem_integration', input.get('siemIntegration', {}))
            if isinstance(siem, dict):
                siem_enabled = siem.get('enabled', False) or siem.get('active', False)
                siem_details["integrationConfigured"] = siem_enabled
                siem_details["siemTarget"] = siem.get('target', siem.get('type'))
            else:
                siem_enabled = bool(siem)

        # Check for audit log target configuration
        if 'target' in input:
            target = str(input['target']).lower()
            if target in KNOWN_SIEM_TARGETS:
                siem_enabled = True
                siem_details["integrationConfigured"] = True
                siem_details["siemTarget"] = target

        # Check for external logging configuration
        if 'external_logging' in input or 'externalLogging' in input:
            ext_log = input.get('external_logging', input.get('externalLogging', {}))
            if isinstance(ext_log, dict):
                siem_enabled = ext_log.get('enabled', False)
                siem_details["integrationConfigured"] = siem_enabled
                siem_details["siemTarget"] = ext_log.get('destination', ext_log.get('target'))
            else:
                siem_enabled = bool(ext_log)

        # Check for audit events (indicates logging is working)
        if 'audit_events' in input or 'auditEvents' in input or 'events' in input:
            events = input.get('audit_events', input.get('auditEvents', input.get('events', [])))
            if isinstance(events, list):
                siem_details["eventCount"] = len(events)
                if len(events) > 0:
                    # Get most recent event timestamp
                    for event in events:
                        if isinstance(event, dict):
                            timestamp = event.get('timestamp', event.get('created',
                                       event.get('time')))
                            if timestamp:
                                siem_details["lastEventTime"] = timestamp
                                break

        # Check enterprise settings
        if 'enterprise' in input:
            enterprise = input['enterprise']
            if isinstance(enterprise, dict):
                if enterprise.get('siem_enabled', False) or \
                   enterprise.get('external_logging', False) or \
                   enterprise.get('audit_log_enabled', False):
                    siem_enabled = True
                    siem_details["integrationConfigured"] = True

        # Check for logging configuration in settings
        if 'settings' in input:
            settings = input['settings']
            if isinstance(settings, dict):
                logging = settings.get('logging', settings.get('audit', {}))
                if isinstance(logging, dict):
                    if logging.get('external_enabled', False) or \
                       logging.get('siem_enabled', False) or \
                       logging.get('target'):
                        siem_enabled = True
                        siem_details["integrationConfigured"] = True
                        siem_details["siemTarget"] = logging.get('target', logging.get('destination'))

        # Check for specific SIEM integrations
        for siem_name in KNOWN_SIEM_TARGETS:
            if siem_name in input or siem_name.replace('-', '_') in input:
                siem_config = input.get(siem_name, input.get(siem_name.replace('-', '_'), {}))
                if isinstance(siem_config, dict):
                    if siem_config.get('enabled', False) or siem_config.get('configured', False):
                        siem_enabled = True
                        siem_details["integrationConfigured"] = True
                        siem_details["siemTarget"] = siem_name
                        break
                elif siem_config:
                    siem_enabled = True
                    siem_details["integrationConfigured"] = True
                    siem_details["siemTarget"] = siem_name
                    break

        # Check Commander output format
        if 'output' in input:
            output = input['output']
            if isinstance(output, dict):
                target = output.get('target', '').lower()
                if target in KNOWN_SIEM_TARGETS:
                    siem_enabled = True
                    siem_details["integrationConfigured"] = True
                    siem_details["siemTarget"] = target

        return {
            criteria_key: siem_enabled,
            **siem_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
