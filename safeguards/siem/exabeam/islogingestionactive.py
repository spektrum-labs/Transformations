import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Exabeam

    Checks: Whether cloud collectors are configured and actively ingesting
    API Source: /context-management/v1/collectors
    Pass Condition: At least one collector exists and is in active status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogIngestionActive": boolean, "activeCollectors": int, "totalCollectors": int}
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
        collectors = data.get("collectors", data.get("data", data.get("items", [])))
        if not isinstance(collectors, list):
            return {
                "isLogIngestionActive": False,
                "activeCollectors": 0,
                "totalCollectors": 0,
                "error": "Unexpected collectors response format"
            }

        total = len(collectors)
        active = [
            c for c in collectors
            if str(c.get("status", c.get("state", ""))).lower() in {"active", "running", "enabled", "connected"}
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogIngestionActive": result,
            "activeCollectors": len(active),
            "totalCollectors": total
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
