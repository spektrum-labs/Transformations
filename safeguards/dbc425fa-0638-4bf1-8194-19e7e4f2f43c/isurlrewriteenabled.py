def transform(input):
    """
    Evaluates if URL rewrite is enabled

    Parameters:
        input (dict): The JSON data containing Email Security information.

    Returns:
        dict: A dictionary summarizing the URL rewrite information.
    """

    is_url_rewrite_enabled = False
    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']

        if 'urlRewrite' in input:
            is_url_rewrite_enabled = input['urlRewrite']
            
        url_rewrite_info = {
            "isURLRewriteEnabled": is_url_rewrite_enabled
        }
        return url_rewrite_info
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}
        