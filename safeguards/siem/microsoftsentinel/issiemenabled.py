def transform(input):
    """
    Verifies SIEM is active by checking workspace provisioning state

    Parameters:
        input (dict): The JSON data containing Microsoft Sentinel workspace API response

    Returns:
        dict: A dictionary with the isSIEMEnabled evaluation result
    """

    criteria_key = "isSIEMEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        siem_enabled = False
        siem_details = {}

        # Azure Sentinel workspace response
        properties = input.get('properties', input)
        provisioning_state = properties.get('provisioningState', '')

        if provisioning_state.lower() == 'succeeded':
            siem_enabled = True
            siem_details['provisioningState'] = provisioning_state

        # Check workspace features
        features = properties.get('features', {})
        if features:
            siem_details['features'] = features

        # Check SKU
        sku = properties.get('sku', input.get('sku', {}))
        if sku:
            siem_details['sku'] = sku

        # Workspace name
        name = input.get('name', '')
        if name:
            siem_details['workspaceName'] = name

        return {
            criteria_key: siem_enabled,
            **siem_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
