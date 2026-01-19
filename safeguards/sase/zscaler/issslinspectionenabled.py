def transform(input):
    """
    Evaluates if SSL/TLS inspection is enabled in Zscaler ZIA.

    Checks for SSL inspection settings and rules that indicate encrypted
    traffic analysis is active.

    Parameters:
        input (dict): The JSON data from Zscaler ZIA SSL settings endpoint.

    Returns:
        dict: A dictionary summarizing the SSL inspection status.
    """

    try:
        if 'response' in input:
            input = input['response']

        isSSLInspectionEnabled = False
        ssl_rules_count = 0

        # Get SSL inspection settings from response
        ssl_settings = input.get('sslInspectionRules', input.get('responseData', {}))

        # Handle if settings is a dict (single config)
        if isinstance(ssl_settings, dict):
            # Check for SSL inspection enabled flag
            if ssl_settings.get('sslInterceptionEnabled', False):
                isSSLInspectionEnabled = True
            if ssl_settings.get('enabled', False):
                isSSLInspectionEnabled = True
            if ssl_settings.get('sslDecryptionEnabled', False):
                isSSLInspectionEnabled = True

            # Check for inspection certificates (indicates SSL inspection is configured)
            if ssl_settings.get('certificates') or ssl_settings.get('rootCertificate'):
                isSSLInspectionEnabled = True

        # Handle if settings is a list (multiple rules)
        elif isinstance(ssl_settings, list):
            ssl_rules_count = len(ssl_settings)
            if ssl_rules_count > 0:
                isSSLInspectionEnabled = True

                # Check for enabled rules
                for rule in ssl_settings:
                    state = rule.get('state', rule.get('status', '')).upper()
                    if state == 'ENABLED' or rule.get('enabled', False):
                        isSSLInspectionEnabled = True
                        break

        # Check for any SSL-related configuration indicators
        if input.get('sslScanEnabled') or input.get('sslInterception'):
            isSSLInspectionEnabled = True

        ssl_inspection_info = {
            "isSSLInspectionEnabled": isSSLInspectionEnabled,
            "sslRulesCount": ssl_rules_count
        }
        return ssl_inspection_info
    except Exception as e:
        return {"isSSLInspectionEnabled": False, "error": str(e)}
