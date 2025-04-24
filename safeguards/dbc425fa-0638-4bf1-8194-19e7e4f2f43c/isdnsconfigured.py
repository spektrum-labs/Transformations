def transform(input):
    """
    Evaluates if DMARC, DKIM and SPF records are set up properly

    Parameters:
        input (dict): The JSON data containing Email Security information.

    Returns:
        dict: A dictionary summarizing the DMARC, DKIM and SPF records information.
    """

    is_dmarc_configured = False
    is_dkim_configured = False
    is_spf_configured = False
    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']

        if 'dmarc' in input:
            is_dmarc_configured = input['dmarc']
            
        if 'dkim' in input:
            is_dkim_configured = input['dkim']
            
        if 'spf' in input:
            is_spf_configured = input['spf']
            
        dns_info = {
            "isDMARCConfigured": is_dmarc_configured,
            "isDKIMConfigured": is_dkim_configured,
            "isSPFConfigured": is_spf_configured,
            "isDNSConfigured": is_dmarc_configured and is_dkim_configured and is_spf_configured
        }
        return dns_info
    except Exception as e:
        return {"isDNSConfigured": False, "isDMARCConfigured": is_dmarc_configured,"isDKIMConfigured": is_dkim_configured,"isSPFConfigured": is_spf_configured,"error": str(e)}
        