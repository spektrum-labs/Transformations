import json
import ast

def transform(input):
    """
    Evaluates if the password policy is enforced via conditional access policies.

    Parameters:
        input (dict): The JSON data from Microsoft Graph API conditional access policies endpoint
                      (https://graph.microsoft.com/beta/identity/conditionalAccess/policies)

    Returns:
        dict: A dictionary summarizing the password policy enforcement information.
    """

    criteria_key_name = "confirmPasswordPolicyEnforced"
    criteria_key_result = False

    try:
        def _parse_input(input):
            if isinstance(input, str):
                # First try to parse as literal Python string representation
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass

                # If that fails, try to parse as JSON
                try:
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

        # Check if an error response body was returned
        if 'error' in input:
            data_error = input.get('error')
            data_inner_error = data_error.get('innerError', {})
            return {
                criteria_key_name: False,
                'errorSource': 'msgraph_api',
                'errorCode': data_error.get('code'),
                'errorMessage': data_error.get('message'),
                'innerErrorCode': data_inner_error.get('code') if data_inner_error else None,
                'innerErrorMessage': data_inner_error.get('message') if data_inner_error else None
            }

        # Ensure value is type list, replace None if found
        value = input.get('value', [])
        if not isinstance(value, list):
            if value is None:
                value = []
            else:
                value = [input.get('value')]

        # Check for enabled policies that enforce password-related controls
        password_policies = []
        for policy in value:
            # Only consider enabled policies
            if policy.get('state', '').lower() != 'enabled':
                continue

            grant_controls = policy.get('grantControls', {})
            if not grant_controls:
                continue

            built_in_controls = grant_controls.get('builtInControls', [])
            if not isinstance(built_in_controls, list):
                built_in_controls = []

            # Check for password-related controls
            # 'passwordChange' forces users to change password
            # Also check for authentication strength which may include password requirements
            has_password_control = 'passwordChange' in built_in_controls

            # Check for authentication strength (which can enforce password policies)
            auth_strength = grant_controls.get('authenticationStrength')
            has_auth_strength = auth_strength is not None and auth_strength.get('id')

            if has_password_control or has_auth_strength:
                password_policies.append({
                    'id': policy.get('id', ''),
                    'displayName': policy.get('displayName', ''),
                    'state': policy.get('state', ''),
                    'hasPasswordChange': has_password_control,
                    'hasAuthStrength': has_auth_strength
                })

        if len(password_policies) > 0:
            criteria_key_result = True

        transformed_data = {
            criteria_key_name: criteria_key_result,
            'passwordPoliciesCount': len(password_policies),
            'passwordPolicies': password_policies
        }
        return transformed_data

    except Exception as e:
        return {criteria_key_name: False, "error": str(e)}
