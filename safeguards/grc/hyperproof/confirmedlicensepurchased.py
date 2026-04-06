import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Hyperproof

    Checks: Whether the Hyperproof account returns a valid authenticated user profile
    API Source: https://api.hyperproof.app/v1/users/me
    Pass Condition: A valid user object is returned confirming active access

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
        user_id = data.get("id", data.get("userId", ""))
        status = data.get("status", "")
        email = data.get("email", "")

        if isinstance(status, str):
            status = status.lower()

        has_valid_user = bool(user_id) or bool(email)
        has_valid_status = status in {"active", "trial", "enabled"}
        result = has_valid_user or has_valid_status
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status if status else ("active" if has_valid_user else "unknown")
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
