import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for N-able Cove Data Protection

    Checks: Whether backup devices have been registered and inventoried
    API Source: {baseURL}/api/v1/devices
    Pass Condition: At least 1 backup device exists in the inventory

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAssetInventoryComplete": boolean, "totalDevices": int}
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
            total = len(devices)
        elif isinstance(devices, dict):
            total = devices.get("total", devices.get("count", len(devices)))
        else:
            total = 0

        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalDevices": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
