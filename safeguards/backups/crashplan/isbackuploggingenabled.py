# isbackuploggingenabled.py - CrashPlan

import json
import ast

def transform(input):
    """
    Checks if CrashPlan alerting and logging is enabled by verifying
    alert data is accessible and alerts are being generated.

    Parameters:
        input (dict): The JSON data from CrashPlan listAlerts endpoint.

    Returns:
        dict: A dictionary indicating if backup logging is enabled.
    """
    try:
        def parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        # Parse input
        data = parse_input(input)

        # Drill down past response/result wrappers if present
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Get alerts data. The old fallback chain `.get(..., []) or .get(..., [])`
        # defaulted to an empty LIST when none of the three keys were present, and an
        # empty list is falsy, so it fell through every `or` to the final `[]` -- which
        # is STILL a list. `isinstance(alerts, list)` was then True unconditionally, and
        # `is_logging_enabled = True` was hardcoded regardless of any of this. Together,
        # an empty object, an auth-error envelope and any unrecognised body all reported
        # logging enabled. Each key must actually be present now, and the hardcoded
        # `True` is gone.
        alerts = data.get("alerts")
        if alerts is None:
            alerts = data.get("data")
        if alerts is None:
            alerts = data.get("items")

        total_alerts = 0
        alert_types = set()
        recognized_response = False

        if isinstance(alerts, list):
            # A recognised alerts/data/items key being present at all -- even an empty
            # list, meaning the endpoint is reachable and generated nothing today -- is
            # a genuine response, unlike a body with none of these keys.
            recognized_response = True
            total_alerts = len(alerts)
            for alert in alerts:
                alert_type = alert.get("type", alert.get("name", ""))
                if alert_type:
                    alert_types.add(alert_type)

        elif "totalCount" in data:
            recognized_response = True
            total_alerts = data.get("totalCount", 0) or 0

        # Logging is considered enabled only when the listAlerts endpoint actually
        # returned one of its recognised shapes -- not merely because a response of
        # some kind arrived.
        is_logging_enabled = recognized_response

        has_alerts = total_alerts > 0

        return {
            "isBackupLoggingEnabled": is_logging_enabled,
            "totalAlerts": total_alerts,
            "alertTypesFound": list(alert_types),
            "alertingActive": has_alerts
        }

    except json.JSONDecodeError:
        return {"isBackupLoggingEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        # If we get an error but can parse the response, logging may still be enabled
        return {"isBackupLoggingEnabled": False, "error": str(e)}
