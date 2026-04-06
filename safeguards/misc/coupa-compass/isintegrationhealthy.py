import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Coupa Compass (Procurement / Spend Management)

    Checks: Whether the Coupa API is responding with valid authentication
    API Source: GET {baseURL}/api/users
    Pass Condition: API returns a valid response confirming connectivity

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

        # A valid response without errors confirms integration health
        if isinstance(data, list) and len(data) > 0:
            result = True
        elif isinstance(data, dict):
            error = data.get("error", data.get("errors", None))
            if error is None:
                result = True
            elif isinstance(data, dict) and data.get("id"):
                result = True
        # -- END EVALUATION LOGIC --

        return {"isIntegrationHealthy": result}
    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
