import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Lark (Bytedance)

    Checks: Whether the Lark bot is responsive and has a valid identity
    API Source: https://open.larksuite.com/open-apis/bot/v3/info
    Pass Condition: Bot info returns a valid open_id and status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "status": str, "botName": str}
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
        bot = data.get("bot", data.get("data", data))
        if isinstance(bot, dict):
            open_id = bot.get("open_id", "")
            bot_name = bot.get("app_name", bot.get("name", "unknown"))
            status = bot.get("status", "")
        else:
            open_id = data.get("open_id", "")
            bot_name = data.get("app_name", "unknown")
            status = data.get("status", "")

        if isinstance(status, str):
            status = status.lower()

        # A valid open_id in the response means the bot is healthy
        has_valid_id = bool(open_id) and len(str(open_id)) > 0

        # Lark returns code 0 on success
        code = data.get("code", -1)
        result = has_valid_id or code == 0
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "status": status if status else ("healthy" if result else "unknown"),
            "botName": bot_name
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
