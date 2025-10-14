import ast
import json

def transform(input):
    """
    Searches transport rules for actions containing "Disclaimer" OR "SubjectPrefix"
    and ensures matching rules are enforced.

    Parameters:
        input_data (list): The JSON data containing transport rules. If None, loads from data.json

    Returns:
        dict: A dictionary with matching rules and summary
    """

    criteriaKey = "isTransportRuleBannerEnforced"
    
    try:
        # Initialize counters
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

        data = input.get("transportRules")

        banner_rules = []

        for rule in data:
            # First check if rule state is "Enabled"
            if rule.get('State') == 'Enabled':
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
        if any(rule['Mode'] == 'Enforce' for rule in banner_rules):
            is_enabled = True
        else:
            is_enabled = False
        
        return {
            criteriaKey: is_enabled,
            'data': data #,
            #'banner_rules_count': len(banner_rules),
            #'banner_rules': banner_rules,
            #'enabled_banner_rules': [rule for rule in banner_rules if rule['State'] == 'Enabled']
        }
        
    except Exception as e:
        return {
            criteriaKey: False,
            'error': str(e)
        }
    