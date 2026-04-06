import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for AlienVault OTX.

    Checks: Whether pulse events (alerts) are configured and returning data
    API Source: GET https://otx.alienvault.com/api/v1/pulses/events
    Pass Condition: At least one event exists indicating alerting is active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "eventCount": int}
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
        events = data.get("results", data.get("data", data.get("events", [])))
        if not isinstance(events, list):
            events = []

        count = len(events)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "eventCount": count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
