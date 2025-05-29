def transform(input):
    """
    Evaluates if the behavioral monitoring is valid

    Parameters:
        input (dict): The JSON data containing behavioral monitoring information.

    Returns:
        dict: A dictionary summarizing the behavioral monitoring information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
        
        default_value = True if input is not None else False

        is_behavioral_monitoring_valid = input.get('isBehavioralMonitoringValid', default_value)
        behavioral_monitoring_info = {
            "isBehavioralMonitoringValid": is_behavioral_monitoring_valid
        }
        return behavioral_monitoring_info
    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}
        