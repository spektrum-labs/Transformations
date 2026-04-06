import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for MISP.

    Checks: Sightings are being recorded indicating active threat monitoring.
    API Source: POST {baseURL}/sightings/restSearch/event
    Pass Condition: Response contains sighting records from recent activity.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean}
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

        # Check for sightings data
        sightings = data if isinstance(data, list) else data.get("response", data.get("sightings", data.get("results", [])))
        if isinstance(sightings, list) and len(sightings) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data and "message" not in data:
            result = True
        else:
            result = False

        return {"isAlertingConfigured": result}

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
