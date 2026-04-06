import json
import ast


def transform(input):
    """
    Evaluates isNotificationConfigured for Twilio

    Checks: Whether notification configurations are present in the account
    API Source: https://api.twilio.com/2010-04-01/Accounts/{accountSid}/Notifications.json
    Pass Condition: API returns successfully indicating notification system is active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isNotificationConfigured": boolean, "totalNotifications": int}
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
        notifications = data.get("notifications", data.get("data", data.get("items", data.get("results", []))))

        if not isinstance(notifications, list):
            notifications = [notifications] if notifications else []

        total = len(notifications)
        error = data.get("error", data.get("code", None))

        result = error is None
        # -- END EVALUATION LOGIC --

        return {
            "isNotificationConfigured": result,
            "totalNotifications": total
        }

    except Exception as e:
        return {"isNotificationConfigured": False, "error": str(e)}
