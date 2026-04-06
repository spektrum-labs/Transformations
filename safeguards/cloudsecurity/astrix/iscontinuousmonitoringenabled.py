import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Astrix Security

    Checks: Whether Astrix is actively monitoring non-human identities
    API Source: {baseURL}/v1/monitoring/status
    Pass Condition: Monitoring status indicates active surveillance of NHIs

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
        status = data.get("status", data.get("monitoringStatus", data.get("state", "")))

        if isinstance(status, str):
            statusLower = status.lower()
        else:
            statusLower = ""

        active_states = {"active", "enabled", "running", "monitoring"}
        result = statusLower in active_states

        if not result:
            result = bool(data.get("enabled", data.get("active", data.get("monitoring", False))))
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "monitoringStatus": status
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
