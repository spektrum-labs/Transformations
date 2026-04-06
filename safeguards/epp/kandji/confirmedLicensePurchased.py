import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Kandji (EPP)

    Checks: Whether the Kandji tenant is active with a valid subscription
    API Source: GET /api/v1/devices?limit=1
    Pass Condition: API returns a valid response confirming tenant access

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        # ── EVALUATION LOGIC ──
        # Kandji /api/v1/devices returns a list of devices
        # A valid response (even empty list) confirms active subscription
        result = False

        if isinstance(data, list):
            result = True
        elif isinstance(data, dict):
            devices = data.get("results", data.get("devices", data.get("data", None)))
            if devices is not None:
                result = True
            elif not data.get("error") and not data.get("message", "").startswith("4"):
                result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
