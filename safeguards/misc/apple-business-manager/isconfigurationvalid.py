import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for Apple Business Manager

    Checks: Whether MDM servers are registered and configured
    API Source: GET https://mdmenrollment.apple.com/v1/mdmServers
    Pass Condition: At least one MDM server is registered

    Parameters:
        input (dict): JSON data containing API response from mdmServers endpoint

    Returns:
        dict: {"isConfigurationValid": boolean, "serverCount": int}
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
        servers = data.get("data", data.get("mdmServers", data.get("items", [])))
        if not isinstance(servers, list):
            servers = []

        result = len(servers) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isConfigurationValid": result,
            "serverCount": len(servers)
        }

    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
