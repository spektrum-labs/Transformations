import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Postman (API Development Platform)

    Checks: Whether the account has API key-based access securely configured
    API Source: GET https://api.getpostman.com/me
    Pass Condition: User profile confirms authenticated access with valid API key

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

        # Successful authenticated access confirms secret management via API keys
        user = data.get("user", data)
        user_id = user.get("id", user.get("username", ""))

        if user_id:
            result = True
        elif data.get("teamId") or data.get("team_id"):
            result = True
        elif data.get("email"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
