def transform(input):
    """
    EDR/endpoint security deployment status across Liongard device inventory.
    Evaluates device profiles for security agent presence and status.

    Liongard categorizes devices as: Compute (desktops, laptops, tablets, smartphones),
    Network, Storage, IoT/Printer.

    Parameters:
        input (dict): The JSON data containing Liongard device inventory response

    Returns:
        dict: A dictionary with the isEDRDeployed evaluation result
    """

    criteria_key = "isEDRDeployed"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']

        # Get devices array - Liongard returns device profiles
        devices = input.get("data", input.get("devices", input.get("items", [])))
        if isinstance(input, list):
            devices = input

        total_count = len(devices) if isinstance(devices, list) else 0
        deployed_count = 0
        compute_devices = 0
        compute_with_agent = 0

        for device in devices if isinstance(devices, list) else []:
            # Get device category - focus on Compute devices for EDR
            category = str(device.get("category", device.get("deviceCategory", ""))).lower()
            device_type = str(device.get("type", device.get("deviceType", ""))).lower()

            # Count compute devices (desktops, laptops, servers, etc.)
            is_compute = category == "compute" or any(t in device_type for t in
                ['desktop', 'laptop', 'workstation', 'server', 'tablet', 'computer'])

            if is_compute:
                compute_devices += 1

            # Check device status - Green = active/protected
            status = str(device.get("status", device.get("connectionStatus", ""))).lower()
            is_active = status in ["green", "active", "online", "connected", "healthy"]

            # Check if managed (has agent or is monitored)
            is_managed = device.get("managed", device.get("isManaged", False))
            has_agent = device.get("agentInstalled", device.get("hasAgent", False))

            # Check for security-related tags or roles
            tags = device.get("tags", [])
            role = str(device.get("role", "")).lower()
            has_security = any('security' in str(t).lower() or 'edr' in str(t).lower()
                             or 'endpoint' in str(t).lower() for t in tags)

            if is_active or is_managed or has_agent or has_security:
                deployed_count += 1
                if is_compute:
                    compute_with_agent += 1

        # Calculate percentage based on compute devices (primary EDR targets)
        if compute_devices > 0:
            coverage_percentage = (compute_with_agent / compute_devices) * 100
        elif total_count > 0:
            coverage_percentage = (deployed_count / total_count) * 100
        else:
            coverage_percentage = 0.0

        # Consider deployed if >80% coverage
        is_deployed = coverage_percentage >= 80.0

        return {
            criteria_key: is_deployed,
            "totalCount": total_count,
            "computeDevices": compute_devices,
            "deployedCount": deployed_count,
            "coveragePercentage": round(coverage_percentage, 2)
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
