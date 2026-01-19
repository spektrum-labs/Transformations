def transform(input):
    """
    Evaluates if Data Loss Prevention (DLP) policies are configured in Zscaler ZIA.

    Checks for the presence of DLP rules and their enabled status.

    Parameters:
        input (dict): The JSON data from Zscaler ZIA DLP rules endpoint.

    Returns:
        dict: A dictionary summarizing the DLP status.
    """

    try:
        if 'response' in input:
            input = input['response']

        isDLPEnabled = False
        rules_count = 0
        enabled_rules_count = 0

        # Get DLP rules from response
        dlp_rules = input.get('dlpRules', input.get('responseData', []))

        if isinstance(dlp_rules, list):
            rules_count = len(dlp_rules)

            if rules_count > 0:
                isDLPEnabled = True

                # Count enabled rules
                for rule in dlp_rules:
                    state = rule.get('state', rule.get('status', '')).upper()
                    enabled = rule.get('enabled', True)

                    if state == 'ENABLED' or enabled is True:
                        enabled_rules_count += 1

        # Check for DLP dictionaries (indicates DLP is configured)
        dlp_dictionaries = input.get('dlpDictionaries', [])
        if isinstance(dlp_dictionaries, list) and len(dlp_dictionaries) > 0:
            isDLPEnabled = True

        # Check for DLP engines or policies
        if input.get('dlpEnabled') or input.get('dlpEngineEnabled'):
            isDLPEnabled = True

        dlp_info = {
            "isDLPEnabled": isDLPEnabled,
            "rulesCount": rules_count,
            "enabledRulesCount": enabled_rules_count
        }
        return dlp_info
    except Exception as e:
        return {"isDLPEnabled": False, "error": str(e)}
