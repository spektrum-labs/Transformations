def transform(input):
    """
    Evaluates if patch management is enabled in Liongard.
    Checks systems for endpoint inspectors that monitor patch status.

    Liongard's Endpoint Inspectors (Windows Server, Windows Workstation,
    macOS, Linux) provide visibility into system updates and patches.

    Parameters:
        input (dict): The JSON data containing Liongard systems information.

    Returns:
        dict: A dictionary summarizing the patch management status.
    """

    try:
        # Handle nested response structure
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']

        is_patch_management_enabled = False
        systems_with_inspectors = 0
        total_systems = 0
        endpoint_inspectors = 0

        # Check for systems (inspected endpoints)
        systems = input.get('data', input.get('systems', input.get('items', [])))
        if isinstance(input, list):
            systems = input

        if isinstance(systems, list):
            total_systems = len(systems)

            for system in systems:
                # Check inspector type - endpoint inspectors monitor patches
                inspector_type = str(system.get('inspectorType',
                                    system.get('inspector',
                                    system.get('type', '')))).lower()

                # Endpoint inspectors that can report on patches
                is_endpoint_inspector = any(t in inspector_type for t in
                    ['windows', 'macos', 'linux', 'workstation', 'server', 'endpoint'])

                if is_endpoint_inspector:
                    endpoint_inspectors += 1

                # Check if system has recent successful inspection
                status = str(system.get('status', system.get('inspectionStatus', ''))).lower()
                last_inspection = system.get('lastInspection', system.get('lastRun'))

                if (is_endpoint_inspector and
                    (status in ['success', 'completed', 'active', 'green'] or last_inspection)):
                    systems_with_inspectors += 1
                    is_patch_management_enabled = True

        # Calculate coverage
        coverage_percentage = 0.0
        if total_systems > 0:
            coverage_percentage = (systems_with_inspectors / total_systems) * 100

        patch_management_info = {
            "isPatchManagementEnabled": is_patch_management_enabled,
            "totalSystems": total_systems,
            "endpointInspectors": endpoint_inspectors,
            "systemsWithInspectors": systems_with_inspectors,
            "coveragePercentage": round(coverage_percentage, 2)
        }
        return patch_management_info
    except Exception as e:
        return {
            "isPatchManagementEnabled": False,
            "error": str(e)
        }
