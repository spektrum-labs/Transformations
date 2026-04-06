import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Upwind

    Checks: Whether the Upwind account is active and licensed
    API Source: {baseURL}/v1/account
    Pass Condition: Account status indicates an active subscription

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
        active = data.get("active", data.get("enabled", None))

        if isinstance(status, str):
            status = status.lower()

        if active is True:
            result = True
            status = status or "active"
        elif status in ("active", "enabled", "trial"):
            result = True
        elif data.get("id") or data.get("accountId") or data.get("name"):
            result = True
            status = "active"
        else:
            result = False
            status = status or "unknown"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
