import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for ThreatQuotient.

    Checks: Active ThreatQuotient subscription by confirming the user endpoint returns valid account data
    API Source: GET https://{hostname}/api/users/me
    Pass Condition: Response contains valid user profile with authentication confirmation

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str}
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
        has_error = data.get("errors") is not None or data.get("error") is not None
        user_data = data.get("data", data)
        has_user = isinstance(user_data, dict) and (user_data.get("id") is not None or user_data.get("email") is not None)

        result = has_user and not has_error
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
