def transform(input):
    """
    Evaluates if audit logging is enabled for the given IDP

    Parameters:
        input (dict): The JSON data containing IDP information.

    Returns:
        dict: A dictionary summarizing the audit logging information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
            
        audit_logging_info = {  
            "isMFALoggingEnabled": True if input is not None else False
        }
        return audit_logging_info
    except Exception as e:
        return {"isMFALoggingEnabled": False, "error": str(e)}
        