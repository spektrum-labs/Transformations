def transform(input):
    """
    Verifies MDM profiles and policies are properly configured on Addigy devices.
    Checks for active MDM enrollment and profile installation.

    Parameters:
        input (dict): The JSON data containing Addigy devices response

    Returns:
        dict: A dictionary with the isEPPConfigured evaluation result
    """

    criteria_key = "isEPPConfigured"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']

        # Get devices array
        devices = input.get("devices", input.get("data", input.get("items", [])))
        if isinstance(input, list):
            devices = input

        total_count = len(devices) if isinstance(devices, list) else 0
        configured_count = 0

        for device in devices if isinstance(devices, list) else []:
            facts = device.get("facts", device)

            # Check for proper configuration indicators
            mdm_profile = facts.get("mdm_profile_installed", facts.get("profiles", []))
            is_enrolled = facts.get("is_enrolled", facts.get("enrolled", facts.get("mdm_enrolled", False)))

            # Check if device has policies applied
            policies = facts.get("policies", facts.get("policy_id", facts.get("assigned_policies", [])))

            # Device is configured if enrolled and has profiles/policies
            has_profiles = bool(mdm_profile) if not isinstance(mdm_profile, list) else len(mdm_profile) > 0
            has_policies = bool(policies) if not isinstance(policies, list) else len(policies) > 0

            if is_enrolled and (has_profiles or has_policies):
                configured_count += 1

        # Calculate percentage
        config_percentage = 0.0
        if total_count > 0:
            config_percentage = (configured_count / total_count) * 100

        # Consider configured if >80% have proper configuration
        is_configured = config_percentage >= 80.0

        return {
            criteria_key: is_configured,
            "totalCount": total_count,
            "configuredCount": configured_count,
            "configurationPercentage": round(config_percentage, 2)
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
