import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Zendesk.

    Checks: Whether the Zendesk API is reachable and bearer token authentication succeeds.
    API Source: GET https://{subdomain}.zendesk.com/api/v2/users/me.json
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
        user = data.get("user", {})
        if not isinstance(user, dict):
            user = {}

        user_id = user.get("id", data.get("id", ""))
        error = data.get("error", data.get("errors", None))

        result = bool(user_id) and not error
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "responseReceived": bool(data)
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
