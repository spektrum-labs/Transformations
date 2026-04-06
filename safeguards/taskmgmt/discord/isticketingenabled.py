import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Discord

    Checks: Whether channels are retrievable from the Discord guild
    API Source: https://discord.com/api/v10/guilds/{guildId}/channels
    Pass Condition: The API returns a channels array (even if empty)

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "channelCount": int}
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
        channels = data if isinstance(data, list) else data.get("data", data.get("channels", []))

        if isinstance(channels, list):
            result = True
            channel_count = len(channels)
        else:
            result = bool(data)
            channel_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "channelCount": channel_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
