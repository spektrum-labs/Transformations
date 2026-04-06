import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Domo

    Checks: Whether the Domo instance has active licensed users
    API Source: {baseURL}/v1/users
    Pass Condition: At least one active user exists confirming a valid Domo subscription

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "totalUsers": int}
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
        users = data.get("data", data.get("users", data.get("results", data.get("items", []))))

        if isinstance(users, list):
            total = len(users)
        elif isinstance(users, dict):
            total = users.get("totalCount", users.get("total", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "totalUsers": total
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
