import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Greenhouse (Recruiting / ATS)

    Checks: Whether the Greenhouse Harvest API is accessible and returns valid user data
    API Source: GET https://harvest.greenhouse.io/v1/users
    Pass Condition: API returns a valid response with user records

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

        # A valid users response confirms active Greenhouse subscription
        users = data.get("users", data) if isinstance(data, dict) else data
        if isinstance(users, list) and len(users) > 0:
            result = True
        elif isinstance(data, dict) and data.get("id"):
            result = True
        elif isinstance(data, list) and len(data) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
