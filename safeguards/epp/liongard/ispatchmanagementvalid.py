def transform(input):
    """
    Ensures patch management processes exist and inspections are running in Liongard.
    Validates that endpoint inspectors have recent successful inspections.

    Parameters:
        input (dict): The JSON data containing Liongard systems information.

    Returns:
        dict: A dictionary with the isPatchManagementValid evaluation result.
    """

    criteria_key = "isPatchManagementValid"

    try:
        # Handle nested response structure
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']

        is_valid = False
        active_inspections = 0
        total_endpoint_systems = 0

        # Check for systems
        systems = input.get('data', input.get('systems', input.get('items', [])))
        if isinstance(input, list):
            systems = input

        if isinstance(systems, list):
            for system in systems:
                # Check inspector type - focus on endpoint inspectors
                inspector_type = str(system.get('inspectorType',
                                    system.get('inspector',
                                    system.get('type', '')))).lower()

                is_endpoint_inspector = any(t in inspector_type for t in
                    ['windows', 'macos', 'linux', 'workstation', 'server', 'endpoint'])

                if is_endpoint_inspector:
                    total_endpoint_systems += 1

                    # Check inspection status and timing
                    status = str(system.get('status', system.get('inspectionStatus', ''))).lower()
                    is_active = status in ['success', 'completed', 'active', 'green', 'healthy']

                    # Check for scheduled/recurring inspections
                    schedule = system.get('schedule', system.get('launchpointSchedule', {}))
                    has_schedule = bool(schedule)

                    # Check last inspection time
                    last_inspection = system.get('lastInspection', system.get('lastRun',
                                                system.get('lastSuccessfulInspection')))
                    has_recent_inspection = bool(last_inspection)

                    if is_active and (has_schedule or has_recent_inspection):
                        active_inspections += 1

        # Patch management is valid if we have active endpoint inspections
        if total_endpoint_systems > 0:
            coverage = (active_inspections / total_endpoint_systems) * 100
            is_valid = coverage >= 80.0
        elif active_inspections > 0:
            is_valid = True

        return {
            criteria_key: is_valid,
            "totalEndpointSystems": total_endpoint_systems,
            "activeInspections": active_inspections,
            "coveragePercentage": round(coverage if total_endpoint_systems > 0 else 0, 2)
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
