def transform(input):
    """
    Checks if DNSSEC is enabled in Cloudflare

    Parameters:
        input (dict): The JSON data containing Cloudflare DNSSEC API response

    Returns:
        dict: A dictionary with the isDNSSECEnabled evaluation result
    """

    criteria_key = "isDNSSECEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        dnssec_enabled = False
        dnssec_details = {}

        # Cloudflare DNSSEC response
        if isinstance(input, dict):
            status = input.get('status', '')
            if status.lower() == 'active':
                dnssec_enabled = True
            dnssec_details['status'] = status

            # Additional DNSSEC fields
            algorithm = input.get('algorithm', '')
            if algorithm:
                dnssec_details['algorithm'] = algorithm

            ds = input.get('ds', '')
            if ds:
                dnssec_details['hasDS'] = True

        return {
            criteria_key: dnssec_enabled,
            **dnssec_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
