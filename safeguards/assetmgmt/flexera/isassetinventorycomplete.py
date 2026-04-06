import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Flexera IT Asset Management

    Checks: Whether the device inventory contains at least one managed asset
    API Source: GET https://api.flexera.com/fnms/v1/orgs/{orgId}/devices
    Pass Condition: At least one device exists in the inventory

    Parameters:
        input (dict): JSON data containing API response from devices endpoint

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
        devices = data.get("values", data.get("data", data.get("devices", data.get("items", []))))
        total_count = data.get("totalCount", data.get("total", 0))

        if not isinstance(devices, list):
            devices = []

        device_count = len(devices) if len(devices) > 0 else int(total_count)
        result = device_count > 0
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "deviceCount": device_count
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
