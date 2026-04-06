import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for BlinkOps Security Automation

    Checks: Whether connections/integrations are configured in BlinkOps
    API Source: GET https://app.blinkops.com/api/v1/connections
    Pass Condition: Connections data is returned successfully

    Parameters:
        input (dict): JSON data containing API response from connections endpoint

    Returns:
        dict: {"isConfigurationValid": boolean, "connectionCount": int}
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
        error = data.get("error", data.get("errors", None))
        if error:
            return {"isConfigurationValid": False, "connectionCount": 0}

        connections = data.get("connections", data.get("data", data.get("items", [])))
        if not isinstance(connections, list):
            connections = []

        result = len(connections) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isConfigurationValid": result,
            "connectionCount": len(connections)
        }

    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
