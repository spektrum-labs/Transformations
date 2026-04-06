import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Verkada

    Checks: Whether Verkada cameras and devices are online and streaming
    API Source: {baseURL}/cameras/v1/devices
    Pass Condition: At least one camera is online and actively monitoring

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
        cameras = data.get("cameras", data.get("devices", data.get("data", data.get("results", []))))

        if isinstance(cameras, list):
            total = len(cameras)
            active = [c for c in cameras if c.get("status", c.get("connection_status", "")).lower() in ("online", "active", "streaming")]
            if len(active) == 0:
                active = [c for c in cameras if c.get("is_online", c.get("online", False)) is True]
            activeCount = len(active)
        elif isinstance(cameras, dict):
            total = cameras.get("totalCount", cameras.get("total", 0))
            activeCount = cameras.get("onlineCount", cameras.get("online", 0))
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
