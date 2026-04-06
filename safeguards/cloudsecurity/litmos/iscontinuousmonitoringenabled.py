import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Litmos

    Checks: Whether the Litmos LMS is accessible and actively serving users
    API Source: {baseURL}/users?source={source}&limit=1&format=json
    Pass Condition: A valid API response is returned confirming the platform is operational

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "monitoringStatus": str}
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
        monitoring_status = "unknown"

        if isinstance(data, list) and len(data) > 0:
            result = True
            monitoring_status = "active"
        elif isinstance(data, dict):
            status = data.get("status", data.get("state", ""))
            if isinstance(status, str):
                monitoring_status = status.lower()

            active_states = {"active", "enabled", "running", "healthy", "ok"}
            result = monitoring_status in active_states

            if not result:
                users = data.get("data", data.get("users", []))
                if isinstance(users, list) and len(users) > 0:
                    result = True
                    monitoring_status = "active"
        else:
            result = False
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "monitoringStatus": monitoring_status
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
