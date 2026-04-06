import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Spur.

    Checks: Whether IP context lookups return threat classification data
    API Source: GET https://api.spur.us/v2/context/{ip}
    Pass Condition: Response contains valid threat classification or tunnel data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "alertCount": int}
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
        has_error = data.get("error") is not None
        tunnels = data.get("tunnels", [])
        risks = data.get("risks", [])

        if not isinstance(tunnels, list):
            tunnels = []
        if not isinstance(risks, list):
            risks = []

        count = len(tunnels) + len(risks)
        result = not has_error and isinstance(data, dict) and len(data) > 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "alertCount": count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
