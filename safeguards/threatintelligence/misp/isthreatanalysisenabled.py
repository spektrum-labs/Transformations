import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for MISP.

    Checks: Threat intelligence events are accessible via events restSearch.
    API Source: POST {baseURL}/events/restSearch
    Pass Condition: Response contains a non-empty list of threat intelligence events.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean}
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

        # Check for MISP event data
        response_obj = data.get("response", data)
        if isinstance(response_obj, list):
            events = response_obj
        elif isinstance(response_obj, dict):
            events = response_obj.get("Event", response_obj.get("event", []))
            if not isinstance(events, list):
                events = []
        else:
            events = []

        if isinstance(events, list) and len(events) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data and "message" not in data:
            result = True
        else:
            result = False

        return {"isThreatAnalysisEnabled": result}

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
