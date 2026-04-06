import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Zoom.

    Checks: Whether the Zoom API is reachable and Server-to-Server OAuth authentication succeeds.
    API Source: GET https://api.zoom.us/v2/users/me
    Pass Condition: A valid user object is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "responseReceived": boolean}
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
        user_id = data.get("id", "")
        error = data.get("error", data.get("errors", None))
        code = data.get("code", None)

        result = bool(user_id) and not error
        if isinstance(code, int) and code != 200 and code != 0:
            result = False
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "responseReceived": bool(data)
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
