import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Atlassian Organizations

    Checks: Whether the Organizations API is reachable and returns valid data
    API Source: https://api.atlassian.com/admin/v2/orgs/{orgId}
    Pass Condition: A valid organization response is returned

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
        org_data = data.get("data", data)
        result = bool(org_data.get("id", "")) or bool(org_data.get("name", ""))
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "responseReceived": bool(data)
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
