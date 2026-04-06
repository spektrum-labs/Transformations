import json
import ast


def transform(input):
    """
    Evaluates isNotificationConfigured for Lark (Bytedance)

    Checks: Whether message delivery is configured and recent messages exist
    API Source: https://open.larksuite.com/open-apis/im/v1/messages
    Pass Condition: At least one message has been sent or received

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isNotificationConfigured": boolean, "totalMessages": int}
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
        items_container = data.get("data", data)
        if isinstance(items_container, dict):
            messages = items_container.get("items", items_container.get("messages", []))
        else:
            messages = data.get("items", data.get("messages", []))

        if not isinstance(messages, list):
            messages = [messages] if messages else []

        total = len(messages)
        result = total >= 1

        # Lark returns code 0 on success; valid response with items means configured
        code = data.get("code", -1)
        if not result and code == 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {
            "isNotificationConfigured": result,
            "totalMessages": total
        }

    except Exception as e:
        return {"isNotificationConfigured": False, "error": str(e)}
