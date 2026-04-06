import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for Egnyte (Enterprise File Sharing)

    Checks: Whether the Egnyte user info and account type are accessible
    API Source: GET {baseURL}/pubapi/v2/userinfo
    Pass Condition: API returns valid user info with account type

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean}
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

        user_id = data.get("id", "")
        username = data.get("username", "")
        user_type = data.get("userType", "")
        email = data.get("email", "")

        if user_id and username:
            result = True
        elif email and user_type:
            result = True
        elif user_id:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}
    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
