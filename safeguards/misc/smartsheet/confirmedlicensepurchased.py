import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Smartsheet

    Checks: Whether the Smartsheet API token has valid access
    API Source: https://api.smartsheet.com/2.0/users/me
    Pass Condition: A valid user object is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "plan": str, "status": str}
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
        user_id = data.get("id", "")
        account = data.get("account", {})
        account_status = account.get("status", "") if isinstance(account, dict) else ""
        result = bool(user_id) or (bool(data) and "error" not in data)
        status = account_status if account_status else ("active" if result else "inactive")
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": "unknown",
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
