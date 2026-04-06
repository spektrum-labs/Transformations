import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Notion (All-in-One Workspace)

    Checks: Whether the Notion workspace is active via the /users/me endpoint
    API Source: https://api.notion.com/v1/users/me
    Pass Condition: API returns a valid bot user object

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "botName": str, "status": str}
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
        obj_type = data.get("type", "")
        bot_name = data.get("name", "unknown")
        bot_id = data.get("id", "")
        error = data.get("code", data.get("error", None))

        if error:
            result = False
            status = "error"
        elif obj_type == "bot" or bool(bot_id):
            result = True
            status = "active"
        else:
            result = False
            status = "unknown"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "botName": bot_name,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
