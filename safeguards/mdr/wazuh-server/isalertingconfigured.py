import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Wazuh Server MDR

    Checks: Whether alerting is configured in Wazuh Manager by checking the
            alerts configuration section for active alert settings and log levels.

    API Source: GET {baseURL}/manager/configuration?section=alerts
    Pass Condition: The alerts configuration section exists and contains alert
                    settings (e.g., log_alert_level), confirming alerting is configured.

    Parameters:
        input (dict): JSON data containing API response from the manager configuration endpoint

    Returns:
        dict: {"isAlertingConfigured": boolean, "alertLevel": int}
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

        # Wazuh manager configuration returns data under data.affected_items
        config_data = data.get("data", data)
        affected_items = config_data.get("affected_items", config_data.get("items", []))

        alert_level = 0
        alert_config_found = False

        if isinstance(affected_items, list) and len(affected_items) > 0:
            alerts_config = affected_items[0] if isinstance(affected_items[0], dict) else {}
            alerts_section = alerts_config.get("alerts", alerts_config)

            log_alert_level = alerts_section.get("log_alert_level", alerts_section.get("logAlertLevel", None))
            email_alert_level = alerts_section.get("email_alert_level", None)

            if log_alert_level is not None:
                alert_level = int(log_alert_level)
                alert_config_found = True
            elif email_alert_level is not None:
                alert_level = int(email_alert_level)
                alert_config_found = True
        elif isinstance(config_data, dict):
            # Direct config response
            log_alert_level = config_data.get("log_alert_level", config_data.get("alerts", {}).get("log_alert_level", None))
            if log_alert_level is not None:
                alert_level = int(log_alert_level)
                alert_config_found = True

        # Alerting is configured if the alerts section exists with valid settings
        result = alert_config_found

        return {
            "isAlertingConfigured": result,
            "alertLevel": alert_level
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
