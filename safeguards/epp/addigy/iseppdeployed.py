def transform(input):
    """
    Addigy agent deployment percentage across managed endpoints.
    Checks MDM profile installation and agent presence.

    Parameters:
        input (dict): The JSON data containing Addigy devices response

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
        devices = input.get("devices", input.get("data", input.get("items", [])))
        if isinstance(input, list):
            devices = input

        total_count = len(devices) if isinstance(devices, list) else 0
        deployed_count = 0

        for device in devices if isinstance(devices, list) else []:
            facts = device.get("facts", device)

            # Check for MDM profile or agent deployment
            mdm_profile = facts.get("mdm_profile_installed", facts.get("profiles", []))
            agent_status = facts.get("agent_installed", facts.get("addigy_agent", facts.get("agent_id")))
            is_enrolled = facts.get("is_enrolled", facts.get("enrolled", facts.get("mdm_enrolled", False)))

            if mdm_profile or agent_status or is_enrolled:
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
