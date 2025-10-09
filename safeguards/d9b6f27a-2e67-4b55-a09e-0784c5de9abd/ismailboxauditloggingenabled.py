import json
import ast
def transform(input):
    """
    Evaluates if mailbox audit logging is enabled

    Parameters:
        input (dict): The JSON data containing mailbox audit log information.

    Returns:
        dict: A dictionary summarizing the mailbox audit log information.
    """

    criteria_key_name = "isMailboxAuditLoggingEnabled"
    criteria_key_result = False

    try:
        def _parse_input(input):
            if isinstance(input, str):
                # First try to parse as literal Python string representation
                try:
                    # Use ast.literal_eval to safely parse Python literal
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                
                # If that fails, try to parse as JSON
                try:
                    # Replace single quotes with double quotes for JSON
                    #input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
                    
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        input = _parse_input(input)
        if 'response' in input:
            input = _parse_input(input['response'])
        if 'result' in input:
            input = _parse_input(input['result'])
            if 'apiResponse' in input:
                input = _parse_input(input['apiResponse'])
            if 'result' in input:
                input = _parse_input(input['result'])
        if 'Output' in input:
            input = _parse_input(input['Output'])

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