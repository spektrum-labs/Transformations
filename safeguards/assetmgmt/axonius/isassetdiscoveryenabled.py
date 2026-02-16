def transform(input):
    """
    Checks if asset discovery adapters are configured and returning devices

    Parameters:
        input (dict): The JSON data containing Axonius devices and adapters API response

    Returns:
        dict: A dictionary with the isAssetDiscoveryEnabled evaluation result
    """

    criteria_key = "isAssetDiscoveryEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        discovery_enabled = False
        discovery_details = {}

        # Check for devices data (merged from getDevices)
        devices = input.get('devices', {})
        if isinstance(devices, dict):
            devices_data = devices.get('apiResponse', devices)
            assets = devices_data.get('assets', devices_data.get('data', []))
            if isinstance(assets, list):
                discovery_details['deviceCount'] = len(assets)
                discovery_enabled = len(assets) > 0

        # Check for adapters data (merged from getAdapters)
        adapters = input.get('adapters', {})
        if isinstance(adapters, dict):
            adapters_data = adapters.get('apiResponse', adapters)
            adapter_list = adapters_data if isinstance(adapters_data, list) else adapters_data.get('data', [])
            if isinstance(adapter_list, list):
                active_adapters = [a for a in adapter_list if a.get('status', '') == 'success' or a.get('node_name')]
                discovery_details['adapterCount'] = len(adapter_list)
                discovery_details['activeAdapters'] = len(active_adapters)
                if len(active_adapters) > 0:
                    discovery_enabled = True

        # Fallback: check for any data presence
        if not discovery_enabled and 'data' in input:
            data = input['data']
            if isinstance(data, list) and len(data) > 0:
                discovery_enabled = True
                discovery_details['dataCount'] = len(data)

        return {
            criteria_key: discovery_enabled,
            **discovery_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
