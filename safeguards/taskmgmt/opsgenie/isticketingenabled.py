import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Opsgenie (Incident Alerting / On-Call)

    Checks: Whether alerts are retrievable from Opsgenie
    API Source: {baseURL}/v2/alerts
    Pass Condition: API returns a list of alerts without error

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "alertCount": int}
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
        alerts = data.get("data", data.get("alerts", []))

        if not isinstance(alerts, list):
            return {
                "isTicketingEnabled": False,
                "alertCount": 0,
                "error": "Unexpected response format"
            }

        alert_count = len(alerts)
        result = alert_count >= 0 and not data.get("error", None)
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "alertCount": alert_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
