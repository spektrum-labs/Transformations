import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Grafana

    Checks: Whether at least one alert rule is configured
    API Source: https://{instance}.grafana.net/api/v1/provisioning/alert-rules
    Pass Condition: At least one alert rule exists

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
        alerts = data if isinstance(data, list) else data.get("alertRules", data.get("data", data.get("items", [])))

        if not isinstance(alerts, list):
            alerts = [alerts] if alerts else []

        total = len(alerts)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "activeAlerts": total,
            "totalAlerts": total
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
