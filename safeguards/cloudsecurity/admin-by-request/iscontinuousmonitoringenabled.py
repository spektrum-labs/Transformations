import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Admin By Request

    Checks: Whether audit logging is actively capturing privileged access events
    API Source: {baseURL}/auditlog
    Pass Condition: Audit log entries exist, indicating active monitoring of privileged access

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
        events = data.get("data", data.get("auditlog", data.get("results", data.get("items", []))))

        if isinstance(events, list):
            total = len(events)
        elif isinstance(events, dict):
            total = events.get("totalCount", events.get("total", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "recentEvents": total
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
