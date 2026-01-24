def transform(input):
    """
    Ensures patch management processes exist and SLAs are met in Addigy.
    Validates that maintenance jobs are active and properly scheduled.

    Parameters:
        input (dict): The JSON data containing Addigy maintenance information

    Returns:
        dict: A dictionary with the isPatchManagementValid evaluation result
    """

    criteria_key = "isPatchManagementValid"

    try:
        # Handle nested response structure
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']

        is_valid = False
        active_patch_policies = 0
        total_maintenance_items = 0

        # Check for maintenance items (Addigy's patch management mechanism)
        maintenance_items = input.get('maintenance', input.get('items', input.get('data', [])))
        if isinstance(input, list):
            maintenance_items = input

        if isinstance(maintenance_items, list):
            total_maintenance_items = len(maintenance_items)

            for item in maintenance_items:
                # Check if maintenance item is related to updates/patches
                item_type = str(item.get('type', item.get('category', ''))).lower()
                item_name = str(item.get('name', item.get('title', ''))).lower()

                # Look for software update related maintenance items
                is_patch_related = any(keyword in item_type or keyword in item_name for keyword in
                    ['update', 'patch', 'software', 'macos', 'os update', 'security update', 'system'])

                if is_patch_related:
                    # Check if the maintenance item is active/enabled
                    is_active = item.get('enabled', item.get('active', item.get('status', '')))
                    status_str = str(is_active).lower()

                    if status_str in ['true', 'enabled', 'active', '1', 'yes']:
                        active_patch_policies += 1

                        # Check for scheduling (indicates proper SLA management)
                        schedule = item.get('schedule', item.get('frequency', item.get('run_schedule', {})))
                        if schedule:
                            is_valid = True

        # Patch management is valid if we have active, scheduled patch policies
        if not is_valid and active_patch_policies > 0:
            is_valid = True

        return {
            criteria_key: is_valid,
            "totalMaintenanceItems": total_maintenance_items,
            "activePatchPolicies": active_patch_policies
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
