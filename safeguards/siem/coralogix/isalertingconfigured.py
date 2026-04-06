import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Coralogix

    Checks: Whether alert definitions are configured and active
    API Source: /api/v1/external/alerts
    Pass Condition: At least one alert definition exists and is active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "activeAlerts": int, "totalAlerts": int}
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
        alerts = data.get("alerts", data.get("data", data.get("items", [])))
        if not isinstance(alerts, list):
            alerts = []

        total = len(alerts)
        active = [
            a for a in alerts
            if a.get("is_active", a.get("active", a.get("enabled", False))) is True
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "activeAlerts": len(active),
            "totalAlerts": total
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
