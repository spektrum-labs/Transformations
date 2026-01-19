def transform(input):
    """
    Evaluates if URL filtering policies are configured and active in Zscaler ZIA.

    Checks for the presence of web application rules and URL filtering configurations.

    Parameters:
        input (dict): The JSON data from Zscaler ZIA URL filtering rules endpoint.

    Returns:
        dict: A dictionary summarizing the URL filtering status.
    """

    try:
        if 'response' in input:
            input = input['response']

        isURLFilteringEnabled = False
        rules_count = 0
        enabled_rules_count = 0

        # Get URL filtering rules from response
        url_rules = input.get('urlFilteringRules', input.get('responseData', []))

        if isinstance(url_rules, list):
            rules_count = len(url_rules)

            if rules_count > 0:
                isURLFilteringEnabled = True

                # Count enabled rules
                for rule in url_rules:
                    state = rule.get('state', rule.get('status', '')).upper()
                    enabled = rule.get('enabled', True)

                    if state == 'ENABLED' or enabled is True:
                        enabled_rules_count += 1

        # Check for URL categories or other URL filtering indicators
        url_categories = input.get('urlCategories', [])
        if isinstance(url_categories, list) and len(url_categories) > 0:
            isURLFilteringEnabled = True

        url_filtering_info = {
            "isURLFilteringEnabled": isURLFilteringEnabled,
            "rulesCount": rules_count,
            "enabledRulesCount": enabled_rules_count
        }
        return url_filtering_info
    except Exception as e:
        return {"isURLFilteringEnabled": False, "error": str(e)}
