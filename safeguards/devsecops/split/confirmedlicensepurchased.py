import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Split (Feature Flag / Experimentation Platform)

    Checks: Whether the Split workspace is accessible via Admin API
    API Source: GET https://api.split.io/internal/api/v2/workspaces
    Pass Condition: API returns valid workspace data confirming active subscription

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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
        result = False

        # A valid workspaces response confirms active Split subscription
        objects = data.get("objects", data.get("data", []))
        if isinstance(objects, list) and len(objects) > 0:
            result = True
        elif data.get("totalCount", data.get("total", 0)) > 0:
            result = True
        elif data.get("id") or data.get("name"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
