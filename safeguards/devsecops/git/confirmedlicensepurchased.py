import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Git (Generic Git Provider)

    Checks: Whether the Git provider account is accessible via API
    API Source: GET {baseURL}/user
    Pass Condition: API returns a valid user object confirming authentication

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

        # A valid user response confirms active Git provider access
        if data.get("id") or data.get("username") or data.get("login"):
            result = True
        elif data.get("name") or data.get("email"):
            result = True
        elif isinstance(data, dict) and len(data) > 0 and not data.get("error"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
