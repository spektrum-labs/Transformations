import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Atlassian Compass (Developer Portal)

    Checks: Whether events are being sent to Compass indicating active CI/CD monitoring
    API Source: GET {baseURL}/v1/events
    Pass Condition: At least one event exists indicating active scanning or monitoring

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
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
        result = False

        # Check for events indicating active scanning or CI/CD monitoring
        events = data.get("values", data.get("data", []))
        if isinstance(events, list) and len(events) > 0:
            result = True
        elif data.get("total", 0) > 0:
            result = True
        elif data.get("size", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
