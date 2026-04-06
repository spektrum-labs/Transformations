import json
import ast


def transform(input):
    """
    Evaluates isUsageMonitored for Anthropic (Claude AI)

    Checks: Whether token counting / usage tracking is functional
    API Source: POST https://api.anthropic.com/v1/messages/count_tokens
    Pass Condition: A valid token count response is returned

    Parameters:
        input (dict): JSON data containing API response from count_tokens endpoint

    Returns:
        dict: {"isUsageMonitored": boolean, "inputTokens": int}
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
        input_tokens = data.get("input_tokens", data.get("tokens", 0))
        error = data.get("error", None)

        if error:
            result = False
            input_tokens = 0
        else:
            result = isinstance(input_tokens, (int, float)) and input_tokens >= 0
        # -- END EVALUATION LOGIC --

        return {
            "isUsageMonitored": result,
            "inputTokens": int(input_tokens) if input_tokens else 0
        }

    except Exception as e:
        return {"isUsageMonitored": False, "error": str(e)}
