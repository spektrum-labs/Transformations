def transform(input):
    """
    Searches transport rules for actions containing "Disclaimer" OR "SubjectPrefix"
    and ensures at least one rule is enabled

    Parameters:
        input_data (list): The JSON data containing transport rules. If None, loads from data.json

    Returns:
        dict: A dictionary with matching rules and summary
    """

    criteriaKey = "isTransportRuleBannerEnabled"
    
    try:
        data = input.get("transportRules")

        banner_rules = []

        for rule in data:
            actions = rule.get('Actions', [])
            if actions:
                # Check if any action contains "Disclaimer" OR "SubjectPrefix"
                matching_actions = [action for action in actions if ('Disclaimer' in action or 'SubjectPrefix' in action)]
                if matching_actions:
                    banner_rules.append({
                        'Name': rule.get('Name', 'Unknown'),
                        'Identity': rule.get('Identity', 'Unknown'),
                        'State': rule.get('State', 'Unknown'),
                        'Mode': rule.get('Mode', 'Unknown'),
                        'Actions': actions,
                        'MatchingActions': matching_actions,
                        'Description': rule.get('Description', '')
                    })

        # Determine if transport rule banner is enabled
        # Consider enabled if there are any enabled banner rules (disclaimer or subject prefix)
        if any(rule['State'] == 'Enabled' for rule in banner_rules):
            is_enabled = True
        else:
            is_enabled = False
        
        return {
            criteriaKey: is_enabled,
            'total_rules': len(data),
            'banner_rules_count': len(banner_rules),
            #'banner_rules': banner_rules,
            #'enabled_banner_rules': [rule for rule in banner_rules if rule['State'] == 'Enabled']
        }
        
    except Exception as e:
        return {
            criteriaKey: False,
            'error': str(e)
        }
    