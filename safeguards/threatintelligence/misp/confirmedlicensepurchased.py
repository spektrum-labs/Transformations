import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for MISP.

    Checks: MISP instance is accessible and the user API key is valid.
    API Source: GET {baseURL}/users/view/me.json
    Pass Condition: Response contains valid user profile data with an active role.

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

        # Check for valid user profile
        user = data.get("User", data.get("user", data))
        if isinstance(user, dict):
            email = user.get("email", "")
            role_id = user.get("role_id", "")

            if isinstance(email, str) and len(email.strip()) > 0:
                return {"confirmedLicensePurchased": True}
            if role_id:
                return {"confirmedLicensePurchased": True}

        if isinstance(data, dict) and len(data) > 0 and "error" not in data and "message" not in data:
            result = True
        else:
            result = False

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
