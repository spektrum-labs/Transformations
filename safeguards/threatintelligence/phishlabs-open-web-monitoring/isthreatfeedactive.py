import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for PhishLabs Open Web Monitoring

    Checks: Whether the PhishLabs Open Web Monitoring indicator feed is returning data
    API Source: GET https://caseapi.phishlabs.com/v1/data/indicators
    Pass Condition: At least one indicator exists in the response

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
        indicators = data.get("data", data.get("results", data.get("indicators", data.get("items", []))))

        if isinstance(indicators, list):
            count = len(indicators)
        elif isinstance(indicators, dict):
            count = 1
        else:
            count = 0

        total = data.get("meta", {}).get("total", count)
        if isinstance(total, (int, float)) and total > count:
            count = int(total)

        result = count > 0
        # -- END EVALUATION LOGIC --

        return {
            "isThreatFeedActive": result,
            "indicatorCount": count
        }

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
