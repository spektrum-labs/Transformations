import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Coupa Compass (Procurement / Spend Management)

    Checks: Whether the Coupa instance is accessible and returns valid user data
    API Source: GET {baseURL}/api/users
    Pass Condition: API returns a valid response with user data

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

        # A valid response from the users endpoint confirms active Coupa subscription
        if isinstance(data, list) and len(data) > 0:
            result = True
        elif isinstance(data, dict):
            user_id = data.get("id", "")
            login = data.get("login", "")
            email = data.get("email", "")
            if user_id or login or email:
                result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
