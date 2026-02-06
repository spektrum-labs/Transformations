import json
import ast


def _parse_input(input):
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
            raise ValueError("Invalid input format")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Validates at least one cloud connector is configured and online

    Parameters:
        input (dict): Connectors API response

    Returns:
        dict: {"hasCloudConnectorsConfigured": boolean, "activeConnectors": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        connectors = data.get("cloudConnectors", [])
        sensors = data.get("sensors", [])

        # Count online connectors
        active_connectors = sum(
            1 for c in connectors
            if c.get("status", "").lower() == "online"
        )

        active_sensors = sum(
            1 for s in sensors
            if s.get("status", "").lower() == "online"
        )

        total_active = active_connectors + active_sensors

        return {
            "hasCloudConnectorsConfigured": total_active > 0,
            "activeConnectors": active_connectors,
            "activeSensors": active_sensors,
            "totalActive": total_active
        }

    except Exception as e:
        return {"hasCloudConnectorsConfigured": False, "error": str(e)}
