import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Intercom (Customer Messaging)

    Checks: Whether the Intercom workspace is active via the /me endpoint
    API Source: https://api.intercom.io/me
    Pass Condition: API returns a valid app object with an active type

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "appName": str, "status": str}
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
        app_type = data.get("type", "")
        app_name = data.get("name", data.get("app", {}).get("name", "unknown"))
        error = data.get("errors", data.get("error", None))

        if error:
            result = False
            status = "error"
        elif app_type in ("admin", "app", "team"):
            result = True
            status = "active"
        else:
            result = bool(data.get("id", None))
            status = "active" if result else "unknown"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "appName": app_name,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
