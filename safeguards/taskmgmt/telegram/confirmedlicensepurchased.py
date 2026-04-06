import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Telegram

    Checks: Whether the Telegram Bot is active and responding
    API Source: https://api.telegram.org/bot{token}/getMe
    Pass Condition: API returns ok=true with bot information

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "botName": str}
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
        bot_result = data.get("result", {})
        bot_name = bot_result.get("first_name", "") if isinstance(bot_result, dict) else ""
        is_bot = bot_result.get("is_bot", False) if isinstance(bot_result, dict) else False

        result = (ok is True or ok == "true") and is_bot
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "botName": bot_name
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
