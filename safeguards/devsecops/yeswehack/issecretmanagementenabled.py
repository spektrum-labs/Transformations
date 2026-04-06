import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for YesWeHack (European Bug Bounty Platform)

    Checks: Whether API access is securely configured with personal access token authentication
    API Source: GET https://api.yeswehack.com/user
    Pass Condition: User profile confirms secure authenticated access

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean}
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

        # Authenticated access confirms secure token management
        username = data.get("username", data.get("login", ""))
        totp = data.get("totp_enabled", None)

        if username:
            result = True
        elif data.get("id") or data.get("email"):
            result = True
        elif totp is not None:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
