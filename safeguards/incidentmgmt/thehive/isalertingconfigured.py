import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for TheHive

    Checks: Whether alert feeds are active and ingesting data in TheHive
    API Source: /api/v1/alert
    Pass Condition: At least one alert exists indicating active feed ingestion

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "totalAlerts": int}
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
        alerts = data.get("alerts", data.get("data", data.get("results", [])))
        if not isinstance(alerts, list):
            alerts = []

        total = len(alerts)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "totalAlerts": total
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
