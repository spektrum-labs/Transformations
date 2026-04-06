import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for ScienceLogic SL1

    Checks: Whether the device inventory contains at least one monitored device
    API Source: GET {baseURL}/api/device
    Pass Condition: At least one device exists in the result set

    Parameters:
        input (dict): JSON data containing API response from device endpoint

    Returns:
        dict: {"isAssetInventoryComplete": boolean, "deviceCount": int}
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
        devices = data.get("result_set", data.get("data", data.get("devices", data.get("items", []))))
        total_matched = data.get("total_matched", data.get("total", 0))

        if not isinstance(devices, list):
            devices = []

        device_count = len(devices) if len(devices) > 0 else int(total_matched)
        result = device_count > 0
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "deviceCount": device_count
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
