import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Zoom.

    Checks: Active Zoom subscription by verifying account settings endpoint
            returns valid account data.
    API Source: GET https://api.zoom.us/v2/accounts/me/settings
    Pass Condition: Account settings are returned with valid data

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
        schedule_meeting = data.get("schedule_meeting", {})
        security = data.get("security", {})
        error = data.get("error", data.get("errors", None))
        code = data.get("code", None)

        if error or (isinstance(code, int) and code != 200 and code != 0):
            result = False
            status = "error"
        elif isinstance(schedule_meeting, dict) and len(schedule_meeting) > 0:
            result = True
            status = "active"
        elif isinstance(security, dict) and len(security) > 0:
            result = True
            status = "active"
        elif isinstance(data, dict) and len(data) > 0 and not error:
            result = True
            status = "active"
        else:
            result = False
            status = "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": "unknown",
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
