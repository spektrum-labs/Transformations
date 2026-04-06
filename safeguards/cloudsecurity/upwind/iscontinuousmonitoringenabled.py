import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Upwind

    Checks: Whether Upwind runtime monitoring is active and reporting
    API Source: {baseURL}/v1/status
    Pass Condition: Platform status indicates active runtime monitoring

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
        statusData = data.get("data", data.get("status", data))

        if isinstance(statusData, dict):
            sensors = statusData.get("sensors", statusData.get("agents", statusData.get("connectedNodes", 0)))
            if isinstance(sensors, int):
                activeCount = sensors
            elif isinstance(sensors, list):
                activeCount = len(sensors)
            else:
                activeCount = 1 if statusData else 0
            total = activeCount
        elif isinstance(statusData, list):
            total = len(statusData)
            activeCount = total
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
