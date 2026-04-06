import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Traliant LMS

    Checks: Whether the Traliant account is active
    API Source: GET {baseURL}/api/v1/account
    Pass Condition: Account status is active or a valid response is returned

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
        status = data.get("status", "")
        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "trial", "ok", "success"}
        result = status in valid_statuses

        if not result:
            account = data.get("account", data.get("data", {}))
            if isinstance(account, dict) and account:
                result = True
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
