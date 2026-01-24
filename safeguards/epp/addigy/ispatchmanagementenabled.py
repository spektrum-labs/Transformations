def transform(input):
    """
    Evaluates if patch management is enabled in Addigy.
    Checks maintenance jobs and policies for patch management configuration.

    Parameters:
        input (dict): The JSON data containing Addigy maintenance/policy information.

    Returns:
        dict: A dictionary summarizing the patch management status.
    """

    try:
        # Handle nested response structure
        if 'response' in input:
            input = input['response']

        default_value = True if input is not None else False

        # Initialize flags
        is_patch_management_enabled = False
        is_patch_management_valid = False
        maintenance_items_count = 0
        patch_policies_count = 0

        # Check for maintenance items (Addigy's patch management mechanism)
        maintenance_items = input.get('maintenance', input.get('items', input.get('data', [])))
        if isinstance(input, list):
            maintenance_items = input

        if isinstance(maintenance_items, list):
            maintenance_items_count = len(maintenance_items)

            for item in maintenance_items:
                # Check if maintenance item is related to updates/patches
                item_type = item.get('type', item.get('category', '')).lower()
                item_name = item.get('name', item.get('title', '')).lower()

                # Look for software update related maintenance items
                if any(keyword in item_type or keyword in item_name for keyword in
                       ['update', 'patch', 'software', 'macos', 'os update', 'security update']):
                    is_patch_management_enabled = True

                    # Check if the maintenance item is active/enabled
                    is_active = item.get('enabled', item.get('active', item.get('status', '')))
                    if is_active and str(is_active).lower() in ['true', 'enabled', 'active', '1']:
                        patch_policies_count += 1

        # Patch management is valid if we have active patch policies
        is_patch_management_valid = patch_policies_count > 0

        # If no specific patch items found but maintenance exists, assume basic coverage
        if maintenance_items_count > 0 and not is_patch_management_enabled:
            is_patch_management_enabled = default_value

        patch_management_info = {
            "isPatchManagementEnabled": is_patch_management_enabled,
            "isPatchManagementValid": is_patch_management_valid,
            "maintenanceItemsCount": maintenance_items_count,
            "activePatchPolicies": patch_policies_count
        }
        return patch_management_info
    except Exception as e:
        return {
            "isPatchManagementEnabled": False,
            "isPatchManagementValid": False,
            "error": str(e)
        }
