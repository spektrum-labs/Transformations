import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for HiBob (HR Platform)

    Checks: Whether the HiBob API is accessible and returns valid profile data
    API Source: GET https://api.hibob.com/v1/profiles
    Pass Condition: API returns a valid response with profile records

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

        # -- EVALUATION LOGIC --
        result = False

        profiles = data.get("profiles", data) if isinstance(data, dict) else data
        if isinstance(profiles, list) and len(profiles) > 0:
            result = True
        elif isinstance(data, dict) and not data.get("error"):
            result = True
        elif isinstance(data, list) and len(data) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
