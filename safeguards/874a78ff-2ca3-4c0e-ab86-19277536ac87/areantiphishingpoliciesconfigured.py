def transform(input):
    """
    Evaluates if anti-phishing is enabled.

    Parameters:
        input (dict): The JSON data containing anti-phishing policy information.

    Returns:
        dict: A dictionary summarizing anti-phishing policy information.
    """

    criteria_key_name = "isAntiPhishingEnabled"
    criteria_key_result = False

    try:
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