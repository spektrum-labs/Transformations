def transform(input):
    """
    Selects secure Score from list returned and evaluates if
    data classification is enabled.

    Parameters:
        input (dict): The JSON data containing all secure Scores.

    Returns:
        dict: A dictionary summarizing data classification status for users.
    """

    criteria_key_name = "isDataClassificationEnabled"
    criteria_key_result = False
    control_name = "mip_sensitivitylabelspolicies"

    try:
        # check if an error response body was returned
        if 'error' in input:
            data_error = input.get('error')
            data_inner_error = data_error.get('innerError')
            return {
                    criteria_key_name: False,
                    'errorSource': 'msgraph_api',
                    'errorCode': data_error.get('code'),
                    'errorMessage': data_error.get('message'),
                    'innerErrorCode': data_inner_error.get('code'),
                    'innerErrorMessage': data_inner_error.get('message')
                    }

        # Ensure value is type list, replace None if found
        value = input.get('value',[])
        if not isinstance(value, list):
            if value is None:
                value = []
            else:
                value = [input.get('value')]

        if len(value) > 1:
            raise ValueError(f"Length of data returned for {criteria_key_name} longer than expected)")

        control_scores = value[0].get('controlScores', [])
        matched_object_list = [i for i in control_scores if i['controlName'] == control_name]

        if len(matched_object_list) > 1:
            raise ValueError(f"More than one object has a controlName of {control_name}. (matched_object_count={len(matched_object_list)})")

        matched_object = matched_object_list[0]
        score_in_percentage = matched_object.get('scoreInPercentage', 0.0)
        if score_in_percentage == 100.00:
            criteria_key_result = True

        transformed_data = {
            criteria_key_name: criteria_key_result
        }
        return transformed_data

    except Exception as e:
        return {criteria_key_name: False, "error": str(e)}