import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for Power BI

    Checks: Whether OAuth credentials can authenticate and retrieve workspace data
    API Source: https://api.powerbi.com/v1.0/myorg/groups
    Pass Condition: A valid workspace response is returned without authentication errors

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean, "responseReceived": boolean}
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
        has_error = "error" in data
        has_data = "value" in data or "workspaces" in data
        result = not has_error and (has_data or bool(data))
        # -- END EVALUATION LOGIC --

        return {
            "isConfigurationValid": result,
            "responseReceived": bool(data)
        }

    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
