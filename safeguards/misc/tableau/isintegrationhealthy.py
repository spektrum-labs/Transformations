import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Tableau

    Checks: Whether the Tableau REST API is reachable and PAT authentication succeeds
    API Source: {serverUrl}/api/{apiVersion}/auth/signin
    Pass Condition: A valid sign-in response is returned from the API

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
        result = bool(data) and "error" not in data
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "responseReceived": bool(data)
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
