import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Google Chronicle SIEM

    Checks: Whether log feeds are configured and actively ingesting data
    API Source: /v2/feeds
    Pass Condition: At least one feed exists with an active state

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogIngestionActive": boolean, "activeFeeds": int, "totalFeeds": int}
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
        feeds = data.get("feeds", data.get("results", data.get("data", [])))
        if not isinstance(feeds, list):
            return {
                "isLogIngestionActive": False,
                "activeFeeds": 0,
                "totalFeeds": 0,
                "error": "Unexpected feeds response format"
            }

        total = len(feeds)
        active = [
            f for f in feeds
            if str(f.get("feedState", f.get("state", ""))).upper() in {"ACTIVE", "ENABLED", "RUNNING"}
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogIngestionActive": result,
            "activeFeeds": len(active),
            "totalFeeds": total
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
