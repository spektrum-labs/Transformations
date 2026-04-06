import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Netskope

    Checks: Whether recent alert events exist indicating active monitoring
    API Source: {baseURL}/api/v2/events/data/alert
    Pass Condition: At least one recent alert event exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "recentEvents": int}
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
        events = data.get("data", data.get("results", data.get("items", data.get("events", []))))

        if not isinstance(events, list):
            events = [events] if events else []

        count = len(events)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "recentEvents": count
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
