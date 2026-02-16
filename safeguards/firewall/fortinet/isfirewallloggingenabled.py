def transform(input):
    """
    Iterates through each policy object to determine if logging is enabled

    Parameters:
        input (dict): The JSON data containing Fortinet firewall log settings API response

    Returns:
        dict: A dictionary with the isFirewallLoggingEnabled evaluation result
    """

    criteria_key = "isFirewallLoggingEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        logging_enabled = False
        logging_details = {}

        # Fortinet log settings response
        results = input.get('results', input)
        if isinstance(results, list) and len(results) > 0:
            settings = results[0] if len(results) > 0 else {}
        elif isinstance(results, dict):
            settings = results
        else:
            settings = input

        # Check log-related fields
        log_disk = settings.get('log-disk', settings.get('logDisk', ''))
        log_fortianalyzer = settings.get('faz-type', settings.get('fazType', ''))
        log_syslogd = settings.get('syslogd', settings.get('log-syslogd', ''))

        if log_disk == 'enable' or log_disk == 'enabled':
            logging_enabled = True
            logging_details['logDisk'] = 'enabled'
        if log_fortianalyzer:
            logging_enabled = True
            logging_details['fortiAnalyzer'] = log_fortianalyzer
        if log_syslogd == 'enable' or log_syslogd == 'enabled':
            logging_enabled = True
            logging_details['syslog'] = 'enabled'

        # Also check if traffic logging is enabled
        traffic_log = settings.get('traffic-log', settings.get('logtraffic', ''))
        if traffic_log == 'enable' or traffic_log == 'all' or traffic_log == 'utm':
            logging_enabled = True
            logging_details['trafficLog'] = traffic_log

        return {
            criteria_key: logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
