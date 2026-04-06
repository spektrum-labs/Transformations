import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Vectra Detect

    Checks: Whether the Vectra brain health indicates active monitoring
    API Source: {baseURL}/api/v2.5/health
    Pass Condition: Health resources (CPU, network, sensors) report healthy status

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
        sensors = data.get("sensors", data.get("Sensors", {}))
        network = data.get("network", data.get("Network", {}))
        system = data.get("system", data.get("System", {}))

        healthyComponents = 0
        totalComponents = 0

        for component in [sensors, network, system]:
            if isinstance(component, dict) and component:
                totalComponents = totalComponents + 1
                compStatus = component.get("status", component.get("state", ""))
                if isinstance(compStatus, str) and compStatus.lower() in ("ok", "healthy", "active", "green"):
                    healthyComponents = healthyComponents + 1
            elif isinstance(component, list) and len(component) > 0:
                totalComponents = totalComponents + 1
                healthyComponents = healthyComponents + 1

        if totalComponents == 0 and data:
            totalComponents = 1
            healthyComponents = 1

        result = healthyComponents > 0
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "activeDevices": healthyComponents,
            "totalDevices": totalComponents
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
