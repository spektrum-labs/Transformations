def transform(input):
    """
    Checks if SSL certificates are managed in Cloudflare

    Parameters:
        input (dict): The JSON data containing Cloudflare SSL settings API response

    Returns:
        dict: A dictionary with the isSSLCertificateManaged evaluation result
    """

    criteria_key = "isSSLCertificateManaged"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        ssl_managed = False
        ssl_details = {}

        # Cloudflare SSL settings response
        if isinstance(input, dict):
            # Check SSL mode
            ssl_mode = input.get('value', input.get('mode', ''))
            if ssl_mode and ssl_mode != 'off':
                ssl_managed = True
                ssl_details['sslMode'] = ssl_mode

            # Check certificate status
            cert_status = input.get('certificate_status', input.get('status', ''))
            if cert_status:
                ssl_details['certificateStatus'] = cert_status
                if cert_status.lower() in ['active', 'issued']:
                    ssl_managed = True

            # Check for certificates list
            certificates = input.get('certificates', input.get('result', []))
            if isinstance(certificates, list) and len(certificates) > 0:
                ssl_managed = True
                ssl_details['certificateCount'] = len(certificates)

        return {
            criteria_key: ssl_managed,
            **ssl_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
