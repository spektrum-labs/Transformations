def transform(input):
    """
    Checks if DNS filtering is enabled via Mark Monitor

    Parameters:
        input (dict): The JSON data containing Mark Monitor DNS records API response

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

        # Check DNS records
        records = input.get('dnsRecords', input.get('records', input.get('data', input.get('value', []))))
        if isinstance(records, list):
            dns_details['totalRecords'] = len(records)
            dns_filtering_enabled = len(records) > 0

            # Check for protective DNS records (e.g., TXT for SPF, DMARC)
            txt_records = [r for r in records if r.get('type', '').upper() == 'TXT']
            dns_details['txtRecords'] = len(txt_records)

        # Check domains
        elif 'domains' in input:
            domains = input['domains']
            if isinstance(domains, list):
                dns_details['totalDomains'] = len(domains)
                dns_filtering_enabled = len(domains) > 0

        return {
            criteria_key: dns_filtering_enabled,
            **dns_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
