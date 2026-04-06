import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Intercom (Customer Messaging)

    Checks: Whether conversations are retrievable from Intercom
    API Source: https://api.intercom.io/conversations
    Pass Condition: API returns a list of conversations without error

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "conversationCount": int}
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
        conversations = data.get("conversations", data.get("data", []))

        if not isinstance(conversations, list):
            return {
                "isTicketingEnabled": False,
                "conversationCount": 0,
                "error": "Unexpected response format"
            }

        conversation_count = len(conversations)
        result = conversation_count >= 0 and not data.get("errors", None)
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "conversationCount": conversation_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
