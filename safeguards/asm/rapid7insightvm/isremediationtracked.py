def transform(input):
    """
    Ensure that processes exist and SLAs are met for vulnerability remediation

    Parameters:
        input (dict): The JSON data containing rapid7insightvm API response

    Returns:
        dict: A dictionary with the isRemediationTracked evaluation result
    """

    criteria_key = "isRemediationTracked"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check remediation tracking
        is_tracked = False
        tracking_details = {}

        # Check for remediation tracking indicators
        if 'remediationTracking' in input or 'trackingEnabled' in input:
            is_tracked = bool(input.get('remediationTracking', input.get('trackingEnabled', False)))
        elif 'retestEnabled' in input or 'retest' in input:
            is_tracked = bool(input.get('retestEnabled', input.get('retest', False)))
        elif 'results' in input:
            results = input['results'] if isinstance(input['results'], list) else []
            # Check if results have remediation/retest data
            tracked_results = [r for r in results if 'remediation' in r or 'retest' in r or 'status' in r]
            is_tracked = len(tracked_results) > 0
            tracking_details['trackedResults'] = len(tracked_results)
            tracking_details['totalResults'] = len(results)
        elif 'workflows' in input:
            workflows = input['workflows'] if isinstance(input['workflows'], list) else []
            is_tracked = len(workflows) > 0
            tracking_details['workflows'] = workflows

        return {
            criteria_key: is_tracked,
            **tracking_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
