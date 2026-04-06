import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for Zendesk.

    Checks: Whether account settings are accessible with the provided API token.
    API Source: GET https://{subdomain}.zendesk.com/api/v2/account/settings.json
    Pass Condition: API returns account settings without authentication errors

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean}
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
        settings = data.get("settings", data.get("account", {}))
        error = data.get("error", data.get("errors", None))
        status_code = data.get("status_code", data.get("statusCode", 200))

        if error:
            result = False
        elif isinstance(status_code, int) and status_code in (401, 403):
            result = False
        elif isinstance(settings, dict) and len(settings) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and not error:
            result = True
        else:
            result = False
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}

    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
