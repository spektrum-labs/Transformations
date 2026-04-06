import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Cribl

    Checks: Whether at least one notification target is configured
    API Source: https://{workspace}.cribl.cloud/api/v1/notifications/targets
    Pass Condition: At least one notification target exists

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
        alerts = data.get("items", data.get("targets", data.get("data", data.get("results", []))))

        if not isinstance(alerts, list):
            alerts = [alerts] if alerts else []

        total = len(alerts)
        active = [a for a in alerts if not a.get("disabled", False)] if alerts else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "activeAlerts": len(active),
            "totalAlerts": total
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
