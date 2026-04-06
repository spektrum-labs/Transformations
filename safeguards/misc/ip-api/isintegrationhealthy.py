import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for IP API (IP Geolocation Service)

    Checks: Whether the IP API is responding and accessible
    API Source: GET https://pro.ip-api.com/json/
    Pass Condition: API returns a valid response with status "success"

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean}
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

        status = data.get("status", "")
        message = data.get("message", "")

        if status == "fail" or message:
            result = False
        elif status == "success":
            result = True
        elif isinstance(data, dict) and data.get("query"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isIntegrationHealthy": result}
    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
