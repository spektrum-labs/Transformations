def transform(input):
    """
    Evaluates the MFA status for  given IDP

    Parameters:
        input (dict): The JSON data containing IDP information.

    Returns:
        dict: A dictionary summarizing the MFA information.
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

        isAntiPhishingEnabled = True
        if len(matching_values) > 0:
            for key,value in matching_values:
                if value is None or not bool(value):
                    isAntiPhishingEnabled = False
                    break

        policy_info = {
            "isAntiPhishingEnabled": isAntiPhishingEnabled,
            "policyDetails": matching_values
        }
        return policy_info
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}
        