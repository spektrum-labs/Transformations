import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Grip Security

    Checks: Whether continuous SaaS discovery and monitoring is active
    API Source: {baseURL}/api/v1/status
    Pass Condition: Platform status indicates active monitoring

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
        status = data.get("status", data.get("state", data.get("monitoringStatus", "")))
        if isinstance(status, str):
            monitoring_status = status.lower()
        else:
            monitoring_status = str(status).lower()

        active_states = {"active", "enabled", "running", "connected", "healthy"}
        result = monitoring_status in active_states

        if not result and data:
            result = bool(
                data.get("monitoring", False) is True
                or data.get("enabled", False) is True
                or data.get("connected", False) is True
            )
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "monitoringStatus": monitoring_status
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
