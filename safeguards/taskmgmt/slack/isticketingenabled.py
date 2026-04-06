import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Slack

    Checks: Whether messages can be retrieved from Slack conversations
    API Source: https://slack.com/api/conversations.history
    Pass Condition: API returns ok=true with messages array

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "messageCount": int}
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
        ok = data.get("ok", False)
        messages = data.get("messages", [])

        if not isinstance(messages, list):
            messages = []

        count = len(messages)
        result = ok is True or ok == "true"
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "messageCount": count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
