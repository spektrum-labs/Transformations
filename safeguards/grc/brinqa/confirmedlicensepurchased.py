import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Brinqa

    Checks: Whether the Brinqa platform authentication is successful, confirming active license
    API Source: {baseURL}/api/auth/login
    Pass Condition: Successful authentication returns a valid token or status

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
        token = data.get("access_token", data.get("token", ""))
        status = data.get("status", "")

        if isinstance(status, str):
            status = status.lower()

        has_token = bool(token)
        has_valid_status = status in {"active", "trial", "enabled", "authenticated"}
        result = has_token or has_valid_status
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status if status else ("authenticated" if has_token else "unknown")
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
