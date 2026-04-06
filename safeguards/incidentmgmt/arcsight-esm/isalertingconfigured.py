import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for ArcSight ESM

    Checks: Whether correlation events (alerts) exist in ArcSight ESM SecurityEventService
    API Source: /www/manager-service/rest/SecurityEventService/getSecurityEvents
    Pass Condition: At least one security event is returned, indicating alerting rules are active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "totalEvents": int}
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
        events = data.get("events", data.get("securityEvents", data.get("data", data.get("results", []))))
        if not isinstance(events, list):
            events = []

        total = len(events)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "totalEvents": total
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
