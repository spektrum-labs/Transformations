def transform(input):
    """
    Makes sure that new internet-exposed assets and shadow IT are uncovered

    Parameters:
        input (dict): The JSON data containing rapid7insightvm API response

    Returns:
        dict: A dictionary with the isContinuousDiscoveryEnabled evaluation result
    """

    criteria_key = "isContinuousDiscoveryEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check scan/discovery status
        is_enabled = False
        scan_details = {}

        # Check for scans
        if 'scans' in input:
            scans = input['scans'] if isinstance(input['scans'], list) else []
            scan_count = len(scans)
            # Check if there are scheduled/active scans
            active_scans = [s for s in scans if s.get('status') in ['scheduled', 'active', 'running', 'enabled']]
            is_enabled = len(active_scans) > 0
            scan_details['totalScans'] = scan_count
            scan_details['activeScans'] = len(active_scans)
        elif 'schedules' in input or 'schedule' in input:
            schedules = input.get('schedules', input.get('schedule', []))
            is_enabled = bool(schedules)
            scan_details['schedules'] = schedules
        elif 'enabled' in input or 'configured' in input:
            is_enabled = bool(input.get('enabled', input.get('configured', False)))
        elif 'continuousDiscovery' in input:
            is_enabled = bool(input['continuousDiscovery'])

        return {
            criteria_key: is_enabled,
            **scan_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
