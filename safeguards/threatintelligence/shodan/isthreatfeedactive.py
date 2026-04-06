import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for Shodan.

    Checks: Whether the host search endpoint returns internet device results
    API Source: GET https://api.shodan.io/shodan/host/search
    Pass Condition: At least one host result is returned

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
        matches = data.get("matches", data.get("results", []))
        if not isinstance(matches, list):
            matches = []

        count = len(matches)
        total = data.get("total", count)
        result = count >= 1 or (isinstance(total, int) and total > 0)
        # -- END EVALUATION LOGIC --

        return {
            "isThreatFeedActive": result,
            "indicatorCount": count
        }

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
