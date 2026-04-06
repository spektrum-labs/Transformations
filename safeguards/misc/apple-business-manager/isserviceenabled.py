import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Apple Business Manager

    Checks: Whether organizational devices are accessible
    API Source: GET https://mdmenrollment.apple.com/v1/orgDevices
    Pass Condition: A valid devices response is returned

    Parameters:
        input (dict): JSON data containing API response from orgDevices endpoint

    Returns:
        dict: {"isServiceEnabled": boolean, "deviceCount": int}
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
        devices = data.get("data", data.get("devices", data.get("items", [])))
        if not isinstance(devices, list):
            devices = []

        result = len(devices) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "deviceCount": len(devices)
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
