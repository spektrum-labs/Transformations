import json
import ast


def transform(input):
    """
    Evaluates isMessagingEnabled for Twilio

    Checks: Whether at least one phone number is provisioned for messaging
    API Source: https://api.twilio.com/2010-04-01/Accounts/{accountSid}/IncomingPhoneNumbers.json
    Pass Condition: At least one incoming phone number exists

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
        channels = data.get("incoming_phone_numbers", data.get("channels", data.get("data", data.get("items", []))))

        if not isinstance(channels, list):
            channels = [channels] if channels else []

        total = len(channels)
        active = [c for c in channels if c.get("status", "in-use") != "released"] if channels else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isMessagingEnabled": result,
            "activeChannels": len(active),
            "totalChannels": total
        }

    except Exception as e:
        return {"isMessagingEnabled": False, "error": str(e)}
