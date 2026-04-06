import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Telegram

    Checks: Whether the Telegram Bot API is responding with valid bot identity
    API Source: https://api.telegram.org/bot{token}/getMe
    Pass Condition: API returns ok=true with bot identity

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "botUsername": str}
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
        bot_username = bot_result.get("username", "") if isinstance(bot_result, dict) else ""

        result = ok is True or ok == "true"
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "botUsername": bot_username
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
