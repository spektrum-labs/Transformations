def transform(input):
    """
    Ensure that anomalous behavior triggers automated alerts and responses

    Parameters:
        input (dict): The JSON data containing synqly_crowdstrike API response

    Returns:
        dict: A dictionary with the isBehavioralMonitoringValid evaluation result
    """

    criteria_key = "isBehavioralMonitoringValid"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check behavioral monitoring
        monitoring_valid = False
        monitoring_details = {}

        # Check for behavioral monitoring indicators
        if 'behavioralMonitoring' in input or 'monitoringEnabled' in input:
            monitoring_valid = bool(input.get('behavioralMonitoring', input.get('monitoringEnabled', False)))
        elif 'alerts' in input:
            alerts = input['alerts'] if isinstance(input['alerts'], list) else []
            monitoring_valid = len(alerts) > 0
            monitoring_details['alerts'] = len(alerts)
        elif 'detections' in input:
            detections = input['detections'] if isinstance(input['detections'], list) else []
            monitoring_valid = len(detections) > 0
            monitoring_details['detections'] = len(detections)
        elif 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            monitoring_policies = [p for p in policies if 'detection' in str(p).lower() or 'prevention' in str(p).lower()]
            monitoring_valid = len(monitoring_policies) > 0
            monitoring_details['monitoringPolicies'] = len(monitoring_policies)
        elif 'enabled' in input:
            monitoring_valid = bool(input['enabled'])

        return {
            criteria_key: monitoring_valid,
            **monitoring_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
