import json
import ast


def transform(input):
    """
    Evaluates isUsageMonitored for Google Gemini AI

    Checks: Whether token counting is functional via the countTokens endpoint
    API Source: POST https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:countTokens
    Pass Condition: A valid totalTokens response is returned

    Parameters:
        input (dict): JSON data containing API response from countTokens endpoint

    Returns:
        dict: {"isUsageMonitored": boolean, "totalTokens": int}
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
        total_tokens = data.get("totalTokens", data.get("total_tokens", 0))
        error = data.get("error", None)

        if error:
            result = False
            total_tokens = 0
        else:
            result = isinstance(total_tokens, (int, float)) and total_tokens >= 0
        # -- END EVALUATION LOGIC --

        return {
            "isUsageMonitored": result,
            "totalTokens": int(total_tokens) if total_tokens else 0
        }

    except Exception as e:
        return {"isUsageMonitored": False, "error": str(e)}
