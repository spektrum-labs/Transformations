import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Intercom (Customer Messaging)

    Checks: Whether the Intercom API is responsive and returning valid workspace data
    API Source: https://api.intercom.io/me
    Pass Condition: API returns a valid response with an app or admin ID

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "status": str}
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
        error = data.get("errors", data.get("error", None))
        has_id = bool(data.get("id", None))

        result = not bool(error) and has_id
        status = "healthy" if result else "unhealthy"
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "status": status
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
