def transform(input):
    """
    Evaluates Mail Policies in place to check for Anti-Phishing settings

    Parameters:
        input (dict): The JSON data containing Mail Policies information.

    Returns:
        dict: A dictionary summarizing the Mail Policies information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
            
        filter_attributes = ["detectDomainNameSpoofing","detectEmployeeNameSpoofing"]

        matching_values = [
            {key: policy["setting"]["value"][key] for key in policy["setting"]["value"] if key in filter_attributes}
            for policy in input["policies"]
            if any(key in policy["setting"]["value"] for key in filter_attributes)
        ]

        isAntiPhishingEnabled = False
        isEmailSecurityEnabled = False

        if len(input["policies"]) > 0:
            isEmailSecurityEnabled = True

        # If any of the matching values are None or False, set isAntiPhishingEnabled to False
        if len(matching_values) > 0:
            isAntiPhishingEnabled = True
            for key,value in matching_values:
                if value is None or not bool(value):
                    isAntiPhishingEnabled = False
                    break

        policy_info = {
            "isEmailSecurityEnabled": isEmailSecurityEnabled,
            "isAntiPhishingEnabled": isAntiPhishingEnabled,
            "policyDetails": matching_values
        }
        return policy_info
    except Exception as e:
        return {"isEmailSecurityEnabled": False, "isAntiPhishingEnabled": False, "error": str(e)}
        