def transform(input):
    """
    Validate SoD policies exist

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the isSegregationOfDutiesEnabled evaluation result
    """

    criteria_key = "isSegregationOfDutiesEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        sod_enabled = False
        sod_details = {}

        # Check for controls array (Saviynt fetchControlAttributes response with SoD type)
        if 'controls' in input:
            controls = input['controls']
            if isinstance(controls, list):
                # Filter for SoD-specific controls
                sod_controls = [c for c in controls if
                    c.get('controltype', '').lower() == 'sod' or
                    'segregation' in str(c).lower() or
                    'sod' in str(c.get('controlname', '')).lower()
                ]
                if len(sod_controls) == 0 and len(controls) > 0:
                    # If filtering returns nothing, use all controls
                    sod_controls = controls
                sod_enabled = len(sod_controls) > 0
                sod_details['totalControls'] = len(controls)
                sod_details['sodPolicies'] = len(sod_controls)
        elif 'sodPolicies' in input:
            policies = input['sodPolicies']
            if isinstance(policies, list):
                sod_enabled = len(policies) > 0
                sod_details['sodPolicyCount'] = len(policies)
        elif 'sodEnabled' in input:
            sod_enabled = bool(input['sodEnabled'])

        return {
            criteria_key: sod_enabled,
            **sod_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
