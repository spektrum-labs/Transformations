import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for VirusTotal.

    Checks: Whether the intelligence search endpoint returns malware indicators
    API Source: GET https://www.virustotal.com/api/v3/intelligence/search
    Pass Condition: At least one malware indicator result is returned

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
        indicators = data.get("data", data.get("results", []))
        if not isinstance(indicators, list):
            indicators = []

        count = len(indicators)
        has_cursor = data.get("links", {}).get("next") is not None if isinstance(data.get("links"), dict) else False
        result = count >= 1 or has_cursor
        # -- END EVALUATION LOGIC --

        return {
            "isThreatFeedActive": result,
            "indicatorCount": count
        }

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
