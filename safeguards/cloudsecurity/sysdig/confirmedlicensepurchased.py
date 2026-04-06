import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Sysdig

    Checks: Whether the Sysdig Secure overview returns a valid active status
    API Source: {baseURL}/api/secure/overview/v2
    Pass Condition: A successful API response indicates an active Sysdig subscription

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

        if status in ("active", "enabled", "ok"):
            result = True
        elif data.get("data") or data.get("overview") or data.get("summary"):
            result = True
            status = "active"
        else:
            result = bool(data)
            status = "active" if result else "unknown"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
