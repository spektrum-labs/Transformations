import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Ardoq

    Checks: Whether the Ardoq instance is operational and the user account is valid
    API Source: {baseURL}/api/v2/me
    Pass Condition: API returns a valid user profile confirming service availability

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "accountActive": boolean}
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
        email = data.get("email", data.get("username", ""))
        org = data.get("organization", data.get("org", data.get("orgLabel", "")))
        role = data.get("role", data.get("roles", ""))

        account_active = bool(email) or bool(org)
        result = account_active
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "accountActive": account_active
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
