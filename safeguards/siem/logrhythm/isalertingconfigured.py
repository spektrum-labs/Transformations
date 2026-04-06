import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for LogRhythm SIEM

    Checks: Whether alert/notification rules are configured and active in
            LogRhythm by checking the notifications endpoint.

    API Source: GET {baseURL}/lr-admin-api/notifications
    Pass Condition: At least one notification rule exists, confirming that
                    alerting is configured for security events.

    Parameters:
        input (dict): JSON data containing API response from the notifications endpoint

    Returns:
        dict: {"isAlertingConfigured": boolean, "alertRuleCount": int}
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

        # LogRhythm notifications endpoint returns a list of notification rules
        notifications = data if isinstance(data, list) else data.get("data", data.get("notifications", []))
        if not isinstance(notifications, list):
            notifications = []

        rule_count = len(notifications)
        active_count = 0

        for rule in notifications:
            enabled = rule.get("isEnabled", rule.get("IsEnabled", True))
            if enabled is not False:
                active_count += 1

        result = active_count > 0

        return {
            "isAlertingConfigured": result,
            "alertRuleCount": rule_count,
            "activeAlertRules": active_count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
