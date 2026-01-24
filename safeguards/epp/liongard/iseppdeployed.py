def transform(input):
    """
    Endpoint protection deployment status across Liongard device inventory.
    Checks device profiles for managed status and active monitoring.

    Parameters:
        input (dict): The JSON data containing Liongard device inventory response

    Returns:
        dict: A dictionary with the isEPPDeployed evaluation result
    """

    criteria_key = "isEPPDeployed"

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
        deployed_count = 0

        for device in devices if isinstance(devices, list) else []:
            # Check device status - Green = active/protected
            status = str(device.get("status", device.get("connectionStatus", ""))).lower()
            is_active = status in ["green", "active", "online", "connected", "healthy"]

            # Check if managed (being monitored by Liongard)
            is_managed = device.get("managed", device.get("isManaged", False))

            # Check lifecycle status
            lifecycle = str(device.get("lifecycleStatus", device.get("lifecycle", ""))).lower()
            is_active_lifecycle = lifecycle in ["active", "production", "deployed", ""]

            # A device is considered to have EPP deployed if it's being monitored
            if (is_active or is_managed) and is_active_lifecycle:
                deployed_count += 1

        # Calculate percentage
        coverage_percentage = 0.0
        if total_count > 0:
            coverage_percentage = (deployed_count / total_count) * 100

        # Consider deployed if >80% coverage
        is_deployed = coverage_percentage >= 80.0

        return {
            criteria_key: is_deployed,
            "totalCount": total_count,
            "deployedCount": deployed_count,
            "coveragePercentage": round(coverage_percentage, 2)
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
