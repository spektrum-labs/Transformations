def transform(input):
    """
    Checks if log retention is properly configured in Microsoft Sentinel

    Parameters:
        input (dict): The JSON data containing Microsoft Sentinel retention settings API response

    Returns:
        dict: A dictionary with the isLogRetentionConfigured evaluation result
    """

    criteria_key = "isLogRetentionConfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        retention_configured = False
        retention_details = {}

        # Azure Log Analytics workspace properties
        properties = input.get('properties', input)
        retention_days = properties.get('retentionInDays', 0)

        if retention_days and retention_days > 0:
            retention_configured = True
            retention_details['retentionInDays'] = retention_days

        # Check workspace capping
        capping = properties.get('workspaceCapping', {})
        if capping:
            daily_quota = capping.get('dailyQuotaGb', -1)
            retention_details['dailyQuotaGb'] = daily_quota

        # Minimum recommended retention is 90 days
        if retention_days >= 90:
            retention_details['meetsMinimumRetention'] = True
        elif retention_days > 0:
            retention_details['meetsMinimumRetention'] = False

        return {
            criteria_key: retention_configured,
            **retention_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
