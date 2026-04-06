import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Panther SIEM

    Checks: Whether alert rules are configured in Panther by checking the
            alerts endpoint for existing alert configurations.

    API Source: GET {baseURL}/v1/alerts
    Pass Condition: At least one alert or detection rule exists, confirming
                    that alerting is configured for security events.

    Parameters:
        input (dict): JSON data containing API response from the alerts endpoint

    Returns:
        dict: {"isAlertingConfigured": boolean, "alertCount": int}
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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Panther returns alerts as a list or under results key
        alerts = data if isinstance(data, list) else data.get("results", data.get("alerts", data.get("data", [])))
        if not isinstance(alerts, list):
            alerts = []

        alert_count = len(alerts)
        result = alert_count > 0

        return {
            "isAlertingConfigured": result,
            "alertCount": alert_count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
