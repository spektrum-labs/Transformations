import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for LaunchDarkly

    Checks: Whether audit logging is active and flag changes are tracked
    API Source: https://app.launchdarkly.com/api/v2/auditlog
    Pass Condition: Audit log entries exist indicating active monitoring

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "auditEntries": int, "recentActivity": boolean}
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
        items = data.get("items", data.get("data", data.get("results", [])))

        if not isinstance(items, list):
            items = []

        total = len(items)
        recent_activity = total > 0

        result = recent_activity
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "auditEntries": total,
            "recentActivity": recent_activity
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
