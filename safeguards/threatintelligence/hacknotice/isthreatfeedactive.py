import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for HackNotice.

    Checks: Whether the indicators endpoint returns threat indicators
    API Source: GET https://api.hacknotice.com/api/v1/indicators
    Pass Condition: At least one indicator is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatFeedActive": boolean, "indicatorCount": int}
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
        indicators = data.get("indicators", data.get("data", data.get("results", [])))
        if not isinstance(indicators, list):
            indicators = []

        count = len(indicators)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isThreatFeedActive": result,
            "indicatorCount": count
        }

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
