def transform(input):
    """
    Ensure that data classification sensitivity labels and policies exist.

    Parameters:
        input (dict): The JSON data containing ms365_dg API response

    Returns:
        dict: A dictionary with the isDataClassificationEnabled evaluation result
    """

    criteria_key = "isDataClassificationEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Check data classification/governance
        is_enabled = False
        classification_details = {}

        # Check for classification indicators
        if 'classificationEnabled' in input or 'dataClassification' in input:
            is_enabled = bool(input.get('classificationEnabled', input.get('dataClassification', False)))
        elif 'enabled' in input:
            is_enabled = bool(input['enabled'])
        elif 'labels' in input:
            labels = input['labels'] if isinstance(input['labels'], list) else []
            is_enabled = len(labels) > 0
            classification_details['labels'] = len(labels)
        elif 'policies' in input:
            policies = input['policies'] if isinstance(input['policies'], list) else []
            is_enabled = len(policies) > 0
            classification_details['policies'] = len(policies)

        return {
            criteria_key: is_enabled,
            **classification_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
