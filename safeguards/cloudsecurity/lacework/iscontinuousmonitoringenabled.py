import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Lacework (FortiCNAPP)

    Checks: Whether alert channels are configured for continuous monitoring
    API Source: {baseURL}/api/v2/AlertChannels
    Pass Condition: At least 1 enabled alert channel exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "activeChannels": int, "totalChannels": int}
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
        channels = data.get("data", data.get("alertChannels", data.get("results", data.get("items", []))))

        if not isinstance(channels, list):
            return {
                "isContinuousMonitoringEnabled": False,
                "activeChannels": 0,
                "totalChannels": 0,
                "error": "Unexpected alert channels response format"
            }

        total = len(channels)

        active = [
            c for c in channels
            if c.get("enabled", False) is True
            or str(c.get("enabled", "")).lower() in ("true", "1")
            or str(c.get("state", "")).lower() in ("enabled", "active")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "activeChannels": len(active),
            "totalChannels": total
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
