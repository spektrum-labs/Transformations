import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Devo

    Checks: Whether log sources are actively sending data to Devo tables
    API Source: /search/query (siem.logtrust.web.activity)
    Pass Condition: Query returns results indicating active log ingestion

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogIngestionActive": boolean, "eventCount": int}
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
        events = data.get("object", data.get("data", data.get("results", [])))
        if isinstance(events, list):
            count = len(events)
        elif isinstance(events, dict):
            count = events.get("count", events.get("total", 1))
        else:
            count = 0

        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogIngestionActive": result,
            "eventCount": count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
