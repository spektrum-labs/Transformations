def transform(input):
    """
    Checks if SIEM logging is enabled by verifying data connectors are configured

    Parameters:
        input (dict): The JSON data containing Microsoft Sentinel data connectors API response

    Returns:
        dict: A dictionary with the isSIEMLoggingEnabled evaluation result
    """

    criteria_key = "isSIEMLoggingEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        logging_enabled = False
        logging_details = {}

        # Azure Sentinel data connectors response
        connectors = input.get('value', [])
        if isinstance(connectors, list):
            total = len(connectors)
            logging_details['totalConnectors'] = total

            connected = []
            for connector in connectors:
                props = connector.get('properties', {})
                state = props.get('dataTypes', {})
                name = connector.get('name', connector.get('kind', ''))

                # Check if any data types are enabled
                is_connected = False
                if isinstance(state, dict):
                    for dt_key, dt_val in state.items():
                        if isinstance(dt_val, dict) and dt_val.get('state', '').lower() == 'enabled':
                            is_connected = True
                            break

                if is_connected:
                    connected.append(name)

            logging_details['connectedSources'] = len(connected)
            logging_enabled = len(connected) > 0

        return {
            criteria_key: logging_enabled,
            **logging_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
