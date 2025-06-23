def transform(input):
    """
    Evaluates if the patch management is enabled

    Parameters:
        input (dict): The JSON data containing patch management information.

    Returns:
        dict: A dictionary summarizing the patch management information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
        
        default_value = True if input is not None else False

        is_patch_management_enabled = input.get('isPatchManagementEnabled', default_value)
        is_patch_management_valid = input.get('isPatchManagementValid', default_value)
        patch_management_info = {
            "isPatchManagementEnabled": is_patch_management_enabled,
            "isPatchManagementValid": is_patch_management_valid
        }
        return patch_management_info
    except Exception as e:
        return {"isPatchManagementEnabled": False,"isPatchManagementValid": False,"error": str(e)}
        