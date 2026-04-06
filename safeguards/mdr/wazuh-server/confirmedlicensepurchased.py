import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Wazuh Server MDR

    Checks: Whether the Wazuh Manager is installed and operational by checking
            the manager info endpoint for a valid version and status response.

    API Source: GET {baseURL}/manager/info
    Pass Condition: The manager info returns a valid Wazuh version string,
                    confirming the Wazuh Manager is installed and running.
                    Wazuh is open source so a running instance confirms deployment.

    Parameters:
        input (dict): JSON data containing API response from the manager info endpoint

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "wazuhVersion": str}
    """
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Wazuh manager/info returns data under data key
        info = data.get("data", data)
        version = info.get("version", info.get("Version", ""))
        compilation_date = info.get("compilation_date", "")
        node_type = info.get("type", info.get("node_type", ""))

        # A valid version string confirms Wazuh is installed and running
        result = bool(version) and "error" not in str(data).lower()

        return {
            "confirmedLicensePurchased": result,
            "wazuhVersion": str(version) if version else "unknown",
            "nodeType": str(node_type) if node_type else "unknown"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
