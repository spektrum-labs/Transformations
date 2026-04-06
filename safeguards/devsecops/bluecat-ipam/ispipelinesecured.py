import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for BlueCat IPAM (IP Address Management)

    Checks: Whether access rights and permissions are configured in Address Manager
    API Source: GET {baseURL}/api/v2/accessRights
    Pass Condition: At least one access right policy exists controlling resource permissions

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean}
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

        # ── EVALUATION LOGIC ──
        result = False

        # Check for access rights indicating security policies
        rights = data if isinstance(data, list) else data.get("data", data.get("accessRights", []))
        if isinstance(rights, list) and len(rights) > 0:
            result = True
        elif isinstance(data, dict) and data.get("count", 0) > 0:
            result = True
        elif isinstance(data, dict) and (data.get("id") or data.get("type")):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
