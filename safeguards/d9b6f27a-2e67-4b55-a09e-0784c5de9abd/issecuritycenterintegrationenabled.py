def transform(input):
    """
    Evaluates if security center integration is enabled.

    Parameters:
        input (dict): The JSON data containing latest email threat submitted.

    Returns:
        dict: A dictionary reflecting if security center integration is enabled.
    """

    criteria_key_name = "isSecurityCenterIntegrationEnabled"
    criteria_key_result = False

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

        if len(value) > 0:
            criteria_key_result = True

        transformed_data = {
            criteria_key_name: criteria_key_result
        }
        return transformed_data

    except Exception as e:
        return {criteria_key_name: False, "error": str(e)}