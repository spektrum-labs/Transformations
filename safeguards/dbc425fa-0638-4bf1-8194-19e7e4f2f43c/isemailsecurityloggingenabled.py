def transform(input):
    """
    Evaluates if email security logging is enabled

    Parameters:
        input (dict): The JSON data containing Email Security information.

    Returns:
        dict: A dictionary summarizing the email security logging information.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
        
        default_value = True if input is not None else False

        email_security_logging_enabled = input.get('isEmailSecurityLoggingEnabled', default_value)
        email_security_logging_info = {
            "isEmailSecurityLoggingEnabled": email_security_logging_enabled
        }
        return email_security_logging_info
    except Exception as e:
        return {"isEmailSecurityLoggingEnabled": False, "error": str(e)}
        