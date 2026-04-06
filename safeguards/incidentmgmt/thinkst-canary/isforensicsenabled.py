import json
import ast


def transform(input):
    """
    Evaluates isForensicsEnabled for Thinkst Canary

    Checks: Whether deployed canary devices and canarytokens are active and reporting
    API Source: /api/v1/devices/all
    Pass Condition: At least one canary device is deployed and online

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isForensicsEnabled": boolean, "totalDevices": int, "onlineDevices": int}
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
        devices = data.get("devices", data.get("data", data.get("results", [])))
        if not isinstance(devices, list):
            devices = []

        total = len(devices)
        online = [
            d for d in devices
            if d.get("live", d.get("online", d.get("status", ""))) in [True, "online", "live"]
        ]

        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isForensicsEnabled": result,
            "totalDevices": total,
            "onlineDevices": len(online)
        }

    except Exception as e:
        return {"isForensicsEnabled": False, "error": str(e)}
