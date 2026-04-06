import json
import ast


def transform(input):
    """
    Evaluates isLogCollectionActive for Pingdom

    Checks: Whether at least one uptime check is configured and active
    API Source: https://api.pingdom.com/api/3.1/checks
    Pass Condition: At least one check exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogCollectionActive": boolean, "activeSources": int, "totalSources": int}
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
        checks = data.get("checks", data.get("data", data.get("items", [])))

        if not isinstance(checks, list):
            checks = [checks] if checks else []

        total = len(checks)
        active = [c for c in checks if c.get("status", "up").lower() in {"up", "active", "paused"}] if checks else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogCollectionActive": result,
            "activeSources": len(active),
            "totalSources": total
        }

    except Exception as e:
        return {"isLogCollectionActive": False, "error": str(e)}
