import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Sysdig

    Checks: Whether Sysdig Secure is actively monitoring and reporting
    API Source: {baseURL}/api/secure/overview/v2
    Pass Condition: The overview returns data indicating active runtime monitoring

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
        overview = data.get("data", data.get("overview", data.get("summary", data)))

        if isinstance(overview, dict):
            agents = overview.get("connectedAgents", overview.get("agents", overview.get("activeAgents", 0)))
            if isinstance(agents, int):
                activeCount = agents
            elif isinstance(agents, list):
                activeCount = len(agents)
            else:
                activeCount = 1 if overview else 0
            total = activeCount
        elif isinstance(overview, list):
            total = len(overview)
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
