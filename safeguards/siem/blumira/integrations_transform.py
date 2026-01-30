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
    Verifies at least one log source integration is streaming data

    Checks both cloud connectors and sensors for active data streaming.

    Parameters:
        input (dict): Connectors/integrations API response

    Returns:
        dict: {"hasActiveIntegrations": boolean, "activeCount": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        connectors = data.get("cloudConnectors", data.get("connectors", []))
        sensors = data.get("sensors", [])

        # Count integrations with recent log activity
        active_connectors = 0
        for c in connectors:
            status = c.get("status", "").lower()
            last_log = c.get("lastLogReceived")
            if status == "online" or last_log:
                active_connectors += 1

        active_sensors = sum(
            1 for s in sensors
            if s.get("status", "").lower() == "online"
        )

        total_active = active_connectors + active_sensors

        return {
            "hasActiveIntegrations": total_active > 0,
            "activeConnectors": active_connectors,
            "activeSensors": active_sensors,
            "totalActiveIntegrations": total_active
        }

    except Exception as e:
        return {"hasActiveIntegrations": False, "error": str(e)}
