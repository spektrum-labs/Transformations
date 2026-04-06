import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for AlgoSec Firewall Analyzer

    Checks: Whether managed devices are configured and monitored in the firewall analyzer
    API Source: {baseURL}/afa/api/v1/devices
    Pass Condition: At least one device is configured and being monitored

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "managedDevices": int}
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
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        devices = data.get("devices", data.get("data", data.get("results", data.get("items", []))))

        if isinstance(devices, list):
            managed = len(devices)
            result = managed > 0
        elif isinstance(devices, dict):
            managed = devices.get("totalCount", devices.get("total", 0))
            result = managed > 0
        else:
            managed = 0
            result = False
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "managedDevices": managed
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
