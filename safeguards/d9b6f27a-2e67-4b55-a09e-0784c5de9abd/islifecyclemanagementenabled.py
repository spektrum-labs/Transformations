def transform(input):
    """
    Evaluates if lifecycle management is enabled for the given IDP

    Parameters:
        input (dict): The JSON data containing IDP information.

    Returns:
        dict: A dictionary summarizing the lifecycle management information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']

        lifecycle_management_info = {  
            "isLifeCycleManagementEnabled": True if input is not None else False
        }
        return lifecycle_management_info
    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}