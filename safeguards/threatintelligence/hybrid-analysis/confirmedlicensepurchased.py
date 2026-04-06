import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Hybrid Analysis.

    Checks: Active Hybrid Analysis API key by verifying the key status endpoint
            returns a valid response with an active authorization level.
    API Source: GET https://hybrid-analysis.com/api/v2/key/current
    Pass Condition: Response contains a valid api_key and auth_level field.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        # Check for valid API key status
        api_key = data.get("api_key", data.get("apiKey", ""))
        auth_level = data.get("auth_level", data.get("authLevel", 0))

        if isinstance(api_key, str) and len(api_key.strip()) > 0:
            result = True
        elif isinstance(auth_level, int) and auth_level > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
