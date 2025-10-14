import json
import ast
def transform(input):
    """
    Evaluates if anti-phishing is enabled.

    Parameters:
        input (dict): The JSON data containing anti-phishing policy information.

    Returns:
        dict: A dictionary summarizing anti-phishing policy information.
    """

    criteria_key_name = "areAntiPhishingPoliciesConfigured"
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

        # check if powershell completed successfully
        if 'PSError' in input:
            ps_error = input.get('PSError')
            #if (ps_error):
            return {
                    criteria_key_name: False,
                    'errorSource': 'PowerShell',
                    'errorMessage': ps_error
            }

        # policies expected as type list
        policies = input.get('policies',[])
        if not isinstance(policies, list):
            if policies is None:
                policies = []
            else:
                policies = [input.get('policies')]

        # rules expected as type list
        rules = input.get('rules',[])
        if not isinstance(rules, list):
            if rules is None:
                rules = []
            else:
                rules = [input.get('rules')]
            
        matching_policies = [
            policy for policy in policies
                if (policy.get("Enabled") is True and
                    # Mailbox Intelligence settings
                    (policy.get("EnableMailboxIntelligence") is True) and
                    (policy.get("EnableMailboxIntelligenceProtection") is True) and
                    (policy.get("TargetedDomainProtectionAction") in ("Quarantine", "MoveToJmf")) and                  # Spoof Intelligence settings
                    # Spoof Intelligence settings
                    (policy.get("EnableSpoofIntelligence") is True) and
                    (policy.get("EnableUnauthenticatedSender") is True) and
                    (policy.get("AuthenticationFailAction") in ("Quarantine", "MoveToJmf")) and
                    # Safety Tips and Indicators settings
                    (policy.get("EnableFirstContactSafetyTips") is True) and 
                    (policy.get("EnableSimilarUsersSafetyTips") is True) and 
                    (policy.get("EnableSimilarDomainsSafetyTips") is True) and 
                    (policy.get("EnableUnusualCharactersSafetyTips") is True) and 
                    (policy.get("EnableViaTag") is True) and
                    # Threshold Settings
                    (policy.get("PhishThresholdLevel") > 1)
                )
        ]

        if len(matching_policies) > 0:
            criteria_key_result = True

        transformed_data = {
            criteria_key_name: criteria_key_result
        }
        return transformed_data

    except Exception as e:
        return {criteria_key_name: False, "error": str(e)}