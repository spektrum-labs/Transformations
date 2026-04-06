import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for IPWHOIS.

    Checks: API response availability confirms the service is operational.
    API Source: GET https://ipwhois.app/json/8.8.8.8
    Pass Condition: Response contains valid data confirming API is accessible.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean}
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

        # Check for valid API response
        success = data.get("success", None)
        ip = data.get("ip", "")

        if success is True:
            result = True
        elif success is False:
            result = False
        elif isinstance(ip, str) and len(ip.strip()) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"isAlertingConfigured": result}

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
