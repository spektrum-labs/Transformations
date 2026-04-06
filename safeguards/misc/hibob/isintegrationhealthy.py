import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for HiBob (HR Platform)

    Checks: Whether the HiBob API is responding with valid authentication
    API Source: GET https://api.hibob.com/v1/profiles
    Pass Condition: API returns a valid response confirming API key connectivity

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

        error = data.get("error", None)

        if error:
            result = False
        elif isinstance(data, list):
            result = True
        elif isinstance(data, dict) and not error:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isIntegrationHealthy": result}
    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
