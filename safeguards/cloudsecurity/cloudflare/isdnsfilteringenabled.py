def transform(input):
    """
    Checks if DNS filtering is enabled in Cloudflare

    Parameters:
        input (dict): The JSON data containing Cloudflare DNS records API response

    Returns:
        dict: A dictionary with the isDNSFilteringEnabled evaluation result
    """

    criteria_key = "isDNSFilteringEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        dns_filtering_enabled = False
        dns_details = {}

        # Cloudflare API returns results in 'result' array
        records = input if isinstance(input, list) else input.get('result', [])
        if isinstance(records, list):
            dns_details['totalRecords'] = len(records)
            dns_filtering_enabled = len(records) > 0

            # Check for proxy-enabled records (indicates DNS filtering)
            proxied = [r for r in records if r.get('proxied', False)]
            dns_details['proxiedRecords'] = len(proxied)
        elif isinstance(input, dict) and 'success' in input:
            dns_filtering_enabled = input.get('success', False)

        return {
            criteria_key: dns_filtering_enabled,
            **dns_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
