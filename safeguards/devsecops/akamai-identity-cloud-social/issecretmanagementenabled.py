import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Akamai Identity Cloud Social

    Checks: Whether Identity Cloud application settings are properly configured
    API Source: {baseURL}/config/{appId}/settings
    Pass Condition: Application settings are present and service is operational

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "configuredSettings": int}
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
        settings = data.get("data", data.get("settings", data.get("configuration", {})))

        if isinstance(settings, dict):
            configured = len(settings.keys())
            result = configured > 0
        elif isinstance(settings, list):
            configured = len(settings)
            result = configured > 0
        else:
            configured = 0
            result = False
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "configuredSettings": configured
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
