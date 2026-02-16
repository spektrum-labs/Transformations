def transform(input):
    """
    Checks if SSL certificates are managed via Mark Monitor

    Parameters:
        input (dict): The JSON data containing Mark Monitor SSL certificates API response

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

        # Check certificates
        certificates = input.get('certificates', input.get('sslCertificates', input.get('data', input.get('value', []))))
        if isinstance(certificates, list):
            ssl_details['totalCertificates'] = len(certificates)
            ssl_managed = len(certificates) > 0

            # Check for valid/active certificates
            active = [c for c in certificates if c.get('status', '').lower() in ['active', 'valid', 'issued']]
            ssl_details['activeCertificates'] = len(active)

            # Check for expiring soon
            expiring = [c for c in certificates if c.get('status', '').lower() in ['expiring', 'warning']]
            if expiring:
                ssl_details['expiringCertificates'] = len(expiring)

        # Check single certificate
        elif 'certificate' in input:
            cert = input['certificate']
            if isinstance(cert, dict):
                ssl_managed = bool(cert)
                ssl_details['certificate'] = cert

        return {
            criteria_key: ssl_managed,
            **ssl_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
