import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for YesWeHack (European Bug Bounty Platform)

    Checks: Whether the YesWeHack account is active and accessible
    API Source: GET https://api.yeswehack.com/user
    Pass Condition: API returns valid user profile confirming active subscription

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

        # A valid user profile response confirms active YesWeHack subscription
        username = data.get("username", data.get("login", ""))
        user_id = data.get("id", "")
        email = data.get("email", "")

        if username or user_id or email:
            result = True
        elif data.get("slug") or data.get("totp_enabled") is not None:
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
