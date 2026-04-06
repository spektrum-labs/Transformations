import json
import ast


def transform(input):
    """
    Evaluates isMessagingEnabled for Lark (Bytedance)

    Checks: Whether the bot has access to at least one chat/channel
    API Source: https://open.larksuite.com/open-apis/im/v1/chats
    Pass Condition: At least one chat is accessible to the bot

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isMessagingEnabled": boolean, "activeChats": int, "totalChats": int}
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
            chats = items_container.get("items", items_container.get("chats", []))
        else:
            chats = data.get("items", data.get("chats", []))

        if not isinstance(chats, list):
            chats = [chats] if chats else []

        total = len(chats)
        active = [
            c for c in chats
            if c.get("chat_status", "normal").lower() in {"normal", "active"}
        ] if chats else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isMessagingEnabled": result,
            "activeChats": len(active),
            "totalChats": total
        }

    except Exception as e:
        return {"isMessagingEnabled": False, "error": str(e)}
