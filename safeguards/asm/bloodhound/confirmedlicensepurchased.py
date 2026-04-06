import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for BloodHound Enterprise (ASM)

    Checks: Whether the BloodHound API returns a valid authenticated user identity
    API Source: {baseURL}/api/v2/self
    Pass Condition: API returns a valid user object with an active session

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

        # ── EVALUATION LOGIC ──
        user_data = data.get("data", data)
        user_id = user_data.get("id", user_data.get("user_id", ""))
        principal_name = user_data.get("principal_name", user_data.get("name", ""))
        status = str(user_data.get("status", "")).lower()

        valid = bool(user_id) and bool(principal_name)
        if status and status in {"disabled", "suspended", "inactive"}:
            valid = False
        # ── END EVALUATION LOGIC ──

        return {
            "confirmedLicensePurchased": valid,
            "status": status if status else "active"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
