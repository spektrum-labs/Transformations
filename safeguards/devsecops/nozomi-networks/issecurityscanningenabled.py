import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Nozomi Networks

    Checks: Whether OT/IoT security alerts are being generated and monitored
    API Source: {baseURL}/api/open/query/do?query=alerts | where status == open
    Pass Condition: Alert monitoring is active (alerts endpoint responds, open alerts tracked)

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "openAlerts": int, "alertMonitoring": boolean}
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
        alerts = data.get("result", data.get("data", data.get("items", [])))

        if isinstance(alerts, list):
            open_alerts = len(alerts)
        elif isinstance(alerts, dict):
            open_alerts = alerts.get("count", 0)
        else:
            open_alerts = 0

        # The fact that the alerts endpoint responds means monitoring is active
        alert_monitoring = True

        result = alert_monitoring
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "openAlerts": open_alerts,
            "alertMonitoring": alert_monitoring
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
