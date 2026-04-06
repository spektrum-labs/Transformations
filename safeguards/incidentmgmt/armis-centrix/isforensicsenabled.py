import json
import ast


def transform(input):
    """
    Evaluates isForensicsEnabled for Armis Centrix

    Checks: Whether device inventory and asset intelligence data is accessible
    API Source: /api/v1/devices/
    Pass Condition: Device inventory returns data indicating forensics capability

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isForensicsEnabled": boolean, "totalDevices": int}
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
        devices = data.get("data", data.get("results", data.get("devices", [])))
        if not isinstance(devices, list):
            devices = []

        total = len(devices)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isForensicsEnabled": result,
            "totalDevices": total
        }

    except Exception as e:
        return {"isForensicsEnabled": False, "error": str(e)}
