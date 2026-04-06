import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Mattermost (Open Source Messaging)

    Checks: Whether channels are configured in Mattermost
    API Source: {baseURL}/api/v4/channels
    Pass Condition: At least 1 channel is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "channelCount": int}
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
        channels = data if isinstance(data, list) else data.get("channels", data.get("results", []))

        if not isinstance(channels, list):
            return {
                "isWorkflowConfigured": False,
                "channelCount": 0,
                "error": "Unexpected response format"
            }

        channel_count = len(channels)
        result = channel_count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "channelCount": channel_count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
