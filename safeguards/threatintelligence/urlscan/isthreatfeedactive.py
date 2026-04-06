import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for URLScan.

    Checks: Whether the search endpoint returns malicious URL scan results
    API Source: GET https://urlscan.io/api/v1/search/?q=task.tags:malicious
    Pass Condition: At least one malicious scan result is returned

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
        results = data.get("results", data.get("data", []))
        if not isinstance(results, list):
            results = []

        count = len(results)
        total = data.get("total", count)
        result = count >= 1 or (isinstance(total, int) and total > 0)
        # -- END EVALUATION LOGIC --

        return {
            "isThreatFeedActive": result,
            "indicatorCount": count
        }

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
