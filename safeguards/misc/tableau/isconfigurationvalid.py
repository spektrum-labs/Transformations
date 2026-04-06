import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for Tableau

    Checks: Whether PAT credentials can authenticate and retrieve site data
    API Source: {serverUrl}/api/{apiVersion}/sites/{siteId}
    Pass Condition: A valid site response is returned without authentication errors

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
        site = data.get("site", {})
        has_site = isinstance(site, dict) and bool(site.get("id", ""))
        result = has_site or (bool(data) and "error" not in data)
        # -- END EVALUATION LOGIC --

        return {
            "isConfigurationValid": result,
            "responseReceived": bool(data)
        }

    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
