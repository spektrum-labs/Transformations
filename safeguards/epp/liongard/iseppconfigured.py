def transform(input):
    """
    Verifies endpoint inspectors and device profiles are properly configured in Liongard.
    Checks for active inspections and proper device categorization.

    Parameters:
        input (dict): The JSON data containing Liongard device inventory response

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
        devices = input.get("data", input.get("devices", input.get("items", [])))
        if isinstance(input, list):
            devices = input

        total_count = len(devices) if isinstance(devices, list) else 0
        configured_count = 0

        for device in devices if isinstance(devices, list) else []:
            # Check if device has proper categorization
            category = device.get("category", device.get("deviceCategory"))
            device_type = device.get("type", device.get("deviceType"))

            has_category = bool(category) and str(category).lower() != "all"
            has_type = bool(device_type)

            # Check device status - not grey (undetermined)
            status = str(device.get("status", device.get("connectionStatus", ""))).lower()
            has_status = status in ["green", "red", "yellow", "active", "inactive"]

            # Check if device has been properly configured with metadata
            has_alias = bool(device.get("alias", device.get("name", device.get("hostname"))))
            has_location = bool(device.get("location"))

            # Check for tags (indicates configuration effort)
            tags = device.get("tags", [])
            has_tags = len(tags) > 0 if isinstance(tags, list) else bool(tags)

            # Device is configured if it has category, status, and identification
            if has_category and has_status and has_alias:
                configured_count += 1
            elif has_type and has_status and (has_tags or has_location):
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
