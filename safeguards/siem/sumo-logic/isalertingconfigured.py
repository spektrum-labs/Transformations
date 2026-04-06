import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Sumo Logic SIEM

    Checks: Whether monitors (alert rules) are configured in Sumo Logic
            by checking the monitors endpoint for active alerting configurations.

    API Source: GET {baseURL}/v1/monitors?limit=50
    Pass Condition: At least one monitor exists, confirming that alerting
                    rules are configured for security and operational monitoring.

    Parameters:
        input (dict): JSON data containing API response from the monitors endpoint

    Returns:
        dict: {"isAlertingConfigured": boolean, "monitorCount": int, "activeMonitors": int}
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

        # Sumo Logic returns monitors under data or children array
        monitors = data if isinstance(data, list) else data.get("data", data.get("children", data.get("monitors", [])))
        if not isinstance(monitors, list):
            monitors = []

        total_count = len(monitors)
        active_count = 0

        for monitor in monitors:
            is_disabled = monitor.get("isDisabled", monitor.get("disabled", False))
            status = monitor.get("status", "")

            if not is_disabled:
                active_count += 1

        result = active_count > 0

        return {
            "isAlertingConfigured": result,
            "monitorCount": total_count,
            "activeMonitors": active_count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
