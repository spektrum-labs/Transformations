import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for N-able N-Central

    Checks: Whether continuous remote monitoring is active
    API Source: {baseURL}/api/server-info
    Pass Condition: N-Central server is operational and monitoring devices

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "monitoringStatus": str, "serverVersion": str}
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
        server_version = data.get("serverVersion", data.get("version", ""))
        status = data.get("status", data.get("state", data.get("monitoringStatus", "")))

        if isinstance(status, str):
            monitoring_status = status.lower()
        else:
            monitoring_status = str(status).lower()

        active_states = {"active", "enabled", "running", "connected", "healthy", "ok"}
        result = monitoring_status in active_states

        if not result and server_version:
            result = True
            monitoring_status = "active"

        if not result and data:
            result = bool(
                data.get("serverId")
                or data.get("serverName")
                or data.get("data")
            )
            if result:
                monitoring_status = "active"
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "monitoringStatus": monitoring_status,
            "serverVersion": str(server_version)
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
