def transform(input):
    """
    Evaluates the MFA status for  given IDP

    Parameters:
        input (dict): The JSON data containing IDP information.

    Returns:
        dict: A dictionary summarizing the MFA information.
    """

    criteria_key_name = "isMFAEnforcedForUsers"
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
        value = input.get('authenticationMethodConfigurations',[])
        if not isinstance(value, list):
            if value is None:
                value = []
            else:
                value = [input.get('authenticationMethodConfigurations')]

        if 'authenticationMethodConfigurations' in input:
            mfa_enrolled = [{"id": obj['id'] if 'id' in obj else '', "state": obj['state'] if 'state' in obj else 'enabled', "includeTargets": obj['includeTargets'] if 'includeTargets' in obj else []} for obj in value if 'state' in obj and str(obj['state']).lower() == "enabled"]
        else:
            mfa_enrolled = []

        if len(mfa_enrolled) > 0:
            criteria_key_result = True

        transformed_data = {
            criteria_key_name: criteria_key_result
        }
        return transformed_data

    except Exception as e:
        return {criteria_key_name: False, "error": str(e)}