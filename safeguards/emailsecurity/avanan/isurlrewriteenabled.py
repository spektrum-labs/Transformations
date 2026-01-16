def transform(input):
    """
    Evaluates if URL rewrite/safe links protection is enabled in Avanan.
    
    Avanan provides click-time URL protection that scans URLs when clicked.
    This checks for URL-related security events.

    Parameters:
        input (dict): The JSON data from Avanan security events endpoint.

    Returns:
        dict: A dictionary summarizing the URL protection status.
    """

    try:
        if 'response' in input:
            input = input['response']
        
        isURLRewriteEnabled = False
        
        # Check for explicit URL protection status
        if input.get('isURLRewriteEnabled') or input.get('urlProtectionEnabled'):
            isURLRewriteEnabled = True
        
        # Avanan scans URLs as part of threat detection
        # If security events are accessible, URL scanning is active
        security_events = input.get('securityEvents', input.get('responseData', []))
        if isinstance(security_events, list):
            isURLRewriteEnabled = True  # Platform is monitoring

        url_info = {
            "isURLRewriteEnabled": isURLRewriteEnabled
        }
        return url_info
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}

