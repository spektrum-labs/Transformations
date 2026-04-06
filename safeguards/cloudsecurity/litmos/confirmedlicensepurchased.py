import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Litmos

    Checks: Whether the Litmos LMS account is active and accessible
    API Source: {baseURL}/users?source={source}&limit=1&format=json
    Pass Condition: A valid API response is returned confirming active account

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
        status = data.get("status", data.get("state", ""))
        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "enabled", "licensed", "trial"}
        result = status in valid_statuses

        if not result and data:
            users = data if isinstance(data, list) else data.get("data", data.get("users", []))
            if isinstance(users, list) and len(users) > 0:
                result = True
                status = "active"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
