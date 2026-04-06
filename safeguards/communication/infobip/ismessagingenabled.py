import json
import ast


def transform(input):
    """
    Evaluates isMessagingEnabled for Infobip

    Checks: Whether at least one messaging channel is configured
    API Source: {baseURL}/ccaas/1/channels
    Pass Condition: At least one channel is present and active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isMessagingEnabled": boolean, "activeChannels": int, "totalChannels": int}
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
        channels = data.get("channels", data.get("data", data.get("items", data.get("results", []))))

        if not isinstance(channels, list):
            channels = [channels] if channels else []

        total = len(channels)
        active = [
            c for c in channels
            if c.get("enabled", True) and c.get("status", "ACTIVE").upper() in {"ACTIVE", "ENABLED", "CONNECTED"}
        ] if channels else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isMessagingEnabled": result,
            "activeChannels": len(active),
            "totalChannels": total
        }

    except Exception as e:
        return {"isMessagingEnabled": False, "error": str(e)}
