import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for TeamViewer

    Checks: Whether TeamViewer devices are actively online and reporting
    API Source: {baseURL}/devices
    Pass Condition: At least one device has an online status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "activeDevices": int, "totalDevices": int}
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
        devices = data.get("devices", data.get("data", data.get("results", data.get("items", []))))

        if isinstance(devices, list):
            total = len(devices)
            active = [d for d in devices if d.get("online_state", d.get("status", "")).lower() in ("online", "active", "busy")]
            activeCount = len(active)
        elif isinstance(devices, dict):
            total = devices.get("totalCount", devices.get("total", 0))
            activeCount = devices.get("onlineCount", devices.get("online", 0))
        else:
            total = 0
            activeCount = 0

        result = activeCount > 0
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "activeDevices": activeCount,
            "totalDevices": total
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
