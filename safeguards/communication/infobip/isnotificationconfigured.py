import json
import ast


def transform(input):
    """
    Evaluates isNotificationConfigured for Infobip

    Checks: Whether notification subscriptions and webhook delivery are configured
    API Source: {baseURL}/push/2/subscriptions
    Pass Condition: At least one subscription exists with a valid notification profile

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isNotificationConfigured": boolean, "totalSubscriptions": int}
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
        subscriptions = data.get("subscriptions", data.get("data", data.get("items", data.get("results", []))))

        if not isinstance(subscriptions, list):
            subscriptions = [subscriptions] if subscriptions else []

        total = len(subscriptions)
        active = [
            s for s in subscriptions
            if s.get("status", "ACTIVE").upper() in {"ACTIVE", "ENABLED"}
        ] if subscriptions else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isNotificationConfigured": result,
            "totalSubscriptions": total,
            "activeSubscriptions": len(active)
        }

    except Exception as e:
        return {"isNotificationConfigured": False, "error": str(e)}
