import json
import ast


def transform(input):
    """
    Evaluates isThreatIntelIntegrated for BloodHound Enterprise (ASM)

    Checks: Whether BloodHound collectors are actively ingesting data
    API Source: {baseURL}/api/v2/collectors
    Pass Condition: At least one collector is in an active/running state with recent data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatIntelIntegrated": boolean, "activeCollectors": int, "totalCollectors": int}
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
        collectors = data.get("data", data.get("collectors", data.get("results", [])))

        if isinstance(collectors, dict):
            collectors = collectors.get("collectors", [])

        if not isinstance(collectors, list):
            return {
                "isThreatIntelIntegrated": False,
                "activeCollectors": 0,
                "totalCollectors": 0,
                "error": "Unexpected collectors response format"
            }

        total = len(collectors)
        active = [
            c for c in collectors
            if str(c.get("status", "")).lower() in {"active", "running", "completed"}
            or c.get("last_checkin") is not None
        ]

        result = len(active) >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isThreatIntelIntegrated": result,
            "activeCollectors": len(active),
            "totalCollectors": total
        }

    except Exception as e:
        return {"isThreatIntelIntegrated": False, "error": str(e)}
